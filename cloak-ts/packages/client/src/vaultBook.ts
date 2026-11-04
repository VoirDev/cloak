import {
  CloakCryptoError,
  encryptionKeyFor,
  equalBytes,
  fromBase64Url,
  isCloakCryptoError,
  logHead,
  openEnvelope,
  replayVaultLog,
  requireCommittedKey,
  unwrapPreviousKey,
  type IdentitySecrets,
  type LogEntry,
  type VaultLogState,
} from '@voirdev/cloak-crypto';

import { CloakKeyUnavailableError } from './CloakKeyUnavailableError.ts';
import { CloakSessionClosedError } from './CloakSessionClosedError.ts';
import { CloakVaultLogError } from './CloakVaultLogError.ts';
import { body, type CloakApi, type Schemas } from './api.ts';
import type { Keyring } from './keyring.ts';
import type { LocalState, LogHead } from './storage/localState.ts';
import { fromWireEntry, validVault } from './wire.ts';

/** A vault as this session verified it. */
export interface VaultRecord {
  /** The verified log. */
  readonly state: VaultLogState;
  /** What the server said about the vault at the last verification, envelope included. */
  readonly view: Schemas['Vault'];
  /**
   * The head this device had verified before this session, if any. Entries and writes after it
   * are checked against superseded keys (`PROTOCOL.md` §7.6 rule 4).
   */
  readonly baselineSeq: number;
}

/** The signed-in user's own keys, as a vault book needs them. */
export interface Self {
  /** Cloak user id. */
  readonly userId: string;
  /** Host user id, which derives [userId] (`PROTOCOL.md` §5.0). */
  readonly hostUserId: string;
  /** Current identity key version. */
  readonly keyVersion: number;
  /** Private keys of the current version, with earlier encryption keys. */
  readonly secrets: IdentitySecrets;
}

/** Where verifying a vault starts. */
interface VaultStart {
  /** State already verified, by this session or in a snapshot; `undefined` to replay from `seq` 1. */
  readonly from: VaultLogState | undefined;
  /** Entries up to this `seq` were verified before (§7.6 rule 4). */
  readonly baselineSeq: number;
  /** The head this device verified last, which the log must pass through. */
  readonly stored: LogHead | undefined;
  /** Log entries are read after this `seq`. */
  readonly afterSeq: number;
}

/**
 * Verified vaults of one session: their logs, replayed incrementally and checked against the
 * heads this device kept (`PROTOCOL.md` §7.6, §15), and their keys, each checked against its
 * commitment before use (§6.1).
 */
export class VaultBook {
  /** HTTP client. */
  readonly #api: CloakApi;
  /** Trusted keys. */
  readonly #keyring: Keyring;
  /** Local state. */
  readonly #local: LocalState;
  /** The signed-in user. */
  readonly #self: Self;
  /** Verified vaults by id. */
  readonly #records = new Map<string, VaultRecord>();
  /** Opened vault keys by vault, then version. */
  readonly #keys = new Map<string, Map<number, Uint8Array>>();
  /** Keys of vaults this session forgot, kept only to be wiped by {@link close}. */
  readonly #retired: Uint8Array[] = [];
  /** Whether {@link close} wiped the keys. */
  #closed = false;

  /**
   * @param api HTTP client.
   * @param keyring Trusted keys.
   * @param local Local state.
   * @param self The signed-in user.
   */
  constructor(api: CloakApi, keyring: Keyring, local: LocalState, self: Self) {
    this.#api = api;
    this.#keyring = keyring;
    this.#local = local;
    this.#self = self;
  }

  /**
   * Returns a vault verified up to the server's current head.
   *
   * @param vaultId The vault.
   * @param refresh Whether to read the server again when this session verified the vault before.
   * @returns The verified vault.
   * @throws {CloakVaultLogError} when the log breaks a rule, rolls back, or disagrees with what the
   *   server says.
   * @throws {CloakKeyChangedError} when a member's keys disagree with what this device trusts.
   */
  async verify(vaultId: string, refresh = true): Promise<VaultRecord> {
    const cached = this.#records.get(vaultId);
    if (cached !== undefined && !refresh) return cached;
    const start = await this.#start(vaultId);
    const view = validVault(
      await body(this.#api.GET('/vaults/{vaultId}', { params: { path: { vaultId } } })),
    );
    return this.#settle(vaultId, start, view, await this.#readLog(vaultId, start.afterSeq));
  }

  /**
   * Verifies several vaults with one request per 100: each vault's view and its next log entries
   * come together, and only a longer log is read on page by page (`PROTOCOL.md` §12.4).
   *
   * @param vaultIds The vaults.
   * @returns Each vault's verified record, or `undefined` when the user cannot see it.
   * @throws {CloakVaultLogError} `state_mismatch` when the server leaves a vault unanswered or
   *   answers for another; as {@link verify} for each vault.
   */
  async verifyMany(vaultIds: readonly string[]): Promise<Map<string, VaultRecord | undefined>> {
    const records = new Map<string, VaultRecord | undefined>();
    const unique = [...new Set(vaultIds)];
    for (let index = 0; index < unique.length; index += 100) {
      const batch = unique.slice(index, index + 100);
      const starts = new Map<string, VaultStart>();
      for (const vaultId of batch) starts.set(vaultId, await this.#start(vaultId));
      const response = await body(
        this.#api.POST('/vaults/batch-get', {
          body: {
            items: batch.map((vaultId) => {
              const afterSeq = starts.get(vaultId)?.afterSeq ?? 0;
              return { vaultId, ...(afterSeq === 0 ? {} : { afterSeq }) };
            }),
          },
        }),
      );
      // Every vault asked must be answered, in order: a vault left out would otherwise look like
      // one the user no longer belongs to.
      if (response.items.length !== batch.length)
        throw new CloakVaultLogError(batch[0] ?? '', 'state_mismatch');
      for (const [position, vaultId] of batch.entries()) {
        const item = response.items[position];
        const start = starts.get(vaultId);
        if (item?.vaultId !== vaultId || start === undefined)
          throw new CloakVaultLogError(vaultId, 'state_mismatch');
        if (!item.found) {
          records.set(vaultId, undefined);
          continue;
        }
        if (item.vault === undefined || item.log === undefined)
          throw new CloakVaultLogError(vaultId, 'state_mismatch');
        const view = validVault(item.vault);
        const entries = [...item.log.items];
        const last = entries.at(-1);
        if (last !== undefined && last.seq < item.log.headSeq)
          entries.push(...(await this.#readLog(vaultId, last.seq)));
        records.set(vaultId, await this.#settle(vaultId, start, view, entries));
      }
    }
    return records;
  }

  /** Where verifying a vault starts: the state this session or device already verified. */
  async #start(vaultId: string): Promise<VaultStart> {
    const cached = this.#records.get(vaultId);
    const stored = await this.#local.head(vaultId);
    let from = cached?.state;
    let baselineSeq = cached?.baselineSeq;
    if (from === undefined) {
      // A snapshot this device kept spares replaying the log from `seq` 1 (§15); one that does
      // not pass through the kept head is ignored, and the log is read whole.
      const snapshot = await this.#local.snapshot(vaultId);
      const point = stored === undefined ? undefined : snapshot?.points[stored.seq - 1];
      if (
        snapshot !== undefined &&
        (stored === undefined || point === undefined || equalBytes(point.hash, stored.entryHash))
      ) {
        from = snapshot;
      }
      baselineSeq = Math.max(stored?.seq ?? 0, from?.points.length ?? 0);
    }
    return { from, baselineSeq: baselineSeq ?? 0, stored, afterSeq: from?.points.length ?? 0 };
  }

  /** Verifies a vault from its start, the server's view and the log entries after the start. */
  async #settle(
    vaultId: string,
    start: VaultStart,
    view: Schemas['Vault'],
    fresh: readonly Schemas['LogEntry'][],
  ): Promise<VaultRecord> {
    if (view.id !== vaultId) throw new CloakVaultLogError(vaultId, 'state_mismatch');
    const { from, baselineSeq, stored } = start;
    const state = await this.#replay(vaultId, fresh, from, baselineSeq);
    const head = logHead(state);

    if (stored !== undefined) {
      const point = state.points[stored.seq - 1];
      if (point === undefined || !equalBytes(point.hash, stored.entryHash))
        throw new CloakVaultLogError(vaultId, 'rollback');
    }
    const me = state.members.get(this.#self.userId);
    if (
      view.logSeq === head.seq &&
      (!equalBytes(fromBase64Url(view.logHeadHash), head.hash) ||
        view.keyVersion !== head.keyVersion ||
        view.role !== me?.role ||
        view.deleted !== state.deleted)
    ) {
      throw new CloakVaultLogError(vaultId, 'state_mismatch');
    }
    if (view.logSeq > head.seq) throw new CloakVaultLogError(vaultId, 'state_mismatch');
    // A head behind what this device verified, kept in memory or in a snapshot, is a rollback.
    if (view.logSeq < head.seq) throw new CloakVaultLogError(vaultId, 'rollback');
    if (fresh.length > 0) await this.#local.raiseSnapshot(vaultId, state);
    // Every member's keys, so the vault's public view can name each member and tell whose keys
    // were replaced; already loaded ones are not fetched again.
    await this.#keyring.load(state.members.keys());
    await this.#local.advanceHead(vaultId, { seq: head.seq, entryHash: head.hash });

    const record: VaultRecord = { state, view, baselineSeq };
    this.#records.set(vaultId, record);
    return record;
  }

  /**
   * Forgets what this session verified about a vault, such as after leaving it.
   *
   * @param vaultId The vault.
   */
  forget(vaultId: string): void {
    // Not wiped: another operation of this session may still be using the key, and a write
    // sealed under a wiped key would be readable by anyone. Only close() wipes, once all are done.
    this.#records.delete(vaultId);
    this.#retired.push(...(this.#keys.get(vaultId)?.values() ?? []));
    this.#keys.delete(vaultId);
  }

  /**
   * Wipes every vault key this session opened and forgets every vault, for a closing session.
   * Later calls of {@link key} fail.
   */
  close(): void {
    this.#closed = true;
    for (const opened of this.#keys.values()) for (const key of opened.values()) key.fill(0);
    for (const key of this.#retired) key.fill(0);
    this.#keys.clear();
    this.#retired.length = 0;
    this.#records.clear();
  }

  /**
   * Returns a vault key, opened from this user's envelope or the key chain and checked against
   * its commitment in the verified log.
   *
   * @param vaultId The vault, verified first.
   * @param keyVersion Version of the key.
   * @returns The 32-byte vault key.
   * @throws {CloakKeyUnavailableError} when this user has no envelope of the current key.
   * @throws {CloakVaultLogError} `key_mismatch` when an opened key is not the committed one.
   */
  async key(vaultId: string, keyVersion: number): Promise<Uint8Array> {
    if (this.#closed) throw new CloakSessionClosedError();
    const opened = this.#keys.get(vaultId) ?? new Map<number, Uint8Array>();
    this.#keys.set(vaultId, opened);
    const known = opened.get(keyVersion);
    if (known !== undefined) return known;

    let record = await this.verify(vaultId, false);
    const current = logHead(record.state).keyVersion;
    if (keyVersion > current) record = await this.verify(vaultId);
    const head = logHead(record.state).keyVersion;
    if (keyVersion > head || keyVersion < 1)
      throw new CloakVaultLogError(vaultId, 'state_mismatch');

    if (!opened.has(head)) opened.set(head, await this.#openEnvelope(vaultId, record, head));
    if (keyVersion === head) return this.#required(opened, head);

    const wraps = await this.#readWraps(vaultId, keyVersion, head);
    for (let version = head; version > keyVersion; version -= 1) {
      if (opened.has(version - 1)) continue;
      const wrapped = wraps.get(version);
      if (wrapped === undefined) throw new CloakVaultLogError(vaultId, 'state_mismatch');
      const previous = this.#checked(vaultId, record, version - 1, () =>
        unwrapPreviousKey(
          this.#required(opened, version),
          vaultId,
          version,
          fromBase64Url(wrapped),
        ),
      );
      opened.set(version - 1, previous);
    }
    return this.#required(opened, keyVersion);
  }

  /**
   * Whether a key version counts as superseded in a vault (`PROTOCOL.md` §7.6 rule 4): this
   * device knows a later version of the person's keys, and the vault's log does not record one.
   * Once the log records the replacement, the old version has no rights after that entry, and the
   * entry's checkpoint settles which earlier writes stand.
   *
   * @param recorded Newest version each person's `member_keys_replaced` entries record.
   * @param userId Person.
   * @param keyVersion Key version.
   * @returns Whether to refuse it.
   */
  isSuperseded(recorded: ReadonlyMap<string, number>, userId: string, keyVersion: number): boolean {
    return (
      this.#keyring.isSuperseded(userId, keyVersion) && (recorded.get(userId) ?? 0) <= keyVersion
    );
  }

  /** Reads the previous-key wraps of versions after [afterVersion] up to [head], page by page. */
  async #readWraps(
    vaultId: string,
    afterVersion: number,
    head: number,
  ): Promise<Map<number, string | undefined>> {
    const wraps = new Map<number, string | undefined>();
    let after = afterVersion;
    while (after < head) {
      const page = await body(
        this.#api.GET('/vaults/{vaultId}/keys', {
          params: { path: { vaultId }, query: { afterVersion: after, limit: 100 } },
        }),
      );
      for (const item of page.items) wraps.set(item.version, item.previousWrappedKey);
      const last = page.items.at(-1);
      if (last === undefined || last.version <= after) break;
      after = last.version;
    }
    return wraps;
  }

  /** Reads log entries after [afterSeq] to the head, page by page. */
  async #readLog(vaultId: string, afterSeq: number): Promise<Schemas['LogEntry'][]> {
    const entries: Schemas['LogEntry'][] = [];
    let after = afterSeq;
    for (;;) {
      const page = await body(
        this.#api.GET('/vaults/{vaultId}/log', {
          params: {
            path: { vaultId },
            query: { ...(after === 0 ? {} : { afterSeq: after }), limit: 100 },
          },
        }),
      );
      entries.push(...page.items);
      const last = page.items.at(-1);
      if (last === undefined || last.seq >= page.headSeq) return entries;
      after = last.seq;
    }
  }

  /**
   * Replays new entries onto [from]: entries up to [baselineSeq], which this device verified
   * before, without the superseded check; the rest with it, except for the user's own entries.
   */
  async #replay(
    vaultId: string,
    fresh: readonly Schemas['LogEntry'][],
    from: VaultLogState | undefined,
    baselineSeq: number,
  ): Promise<VaultLogState> {
    if (fresh.length === 0) {
      if (from !== undefined) return from;
      throw new CloakVaultLogError(vaultId, 'broken_chain', 1);
    }
    await this.#loadKeys(fresh);
    let state = from;
    let previousHash = from === undefined ? undefined : logHead(from).hash;
    const entries: LogEntry[] = fresh.map((wire) => {
      const entry = fromWireEntry(vaultId, wire, previousHash);
      previousHash = entry.entryHash;
      return entry;
    });
    // A later entry that records the replacement lifts rule 4 for the entries before it.
    const recorded = new Map(from?.recordedKeyVersions ?? []);
    for (const entry of fresh) {
      if (entry.kind === 'member_keys_replaced' && entry.subjectKeyVersion !== undefined) {
        recorded.set(
          entry.authorUserId,
          Math.max(recorded.get(entry.authorUserId) ?? 0, entry.subjectKeyVersion),
        );
      }
    }
    const before = entries.filter((entry) => entry.seq <= baselineSeq);
    const after = entries.filter((entry) => entry.seq > baselineSeq);
    for (const [part, checkSuperseded] of [
      [before, false],
      [after, true],
    ] as const) {
      if (part.length === 0) continue;
      const result = replayVaultLog(
        vaultId,
        part,
        {
          keysOf: (userId, keyVersion) => this.#keyring.keysOf(userId, keyVersion),
          // The user's own old keys are exempt: this device must verify the log to record the
          // replacement, and lists what they signed for review instead (§5.6 step 5).
          isSuperseded: checkSuperseded
            ? (userId, keyVersion) =>
                userId !== this.#self.userId && this.isSuperseded(recorded, userId, keyVersion)
            : undefined,
        },
        state,
      );
      if (!result.ok) throw new CloakVaultLogError(vaultId, result.reason, result.failSeq);
      state = result.state;
    }
    if (state === undefined) throw new CloakVaultLogError(vaultId, 'broken_chain', 1);
    return state;
  }

  /** Loads the keys of every author and subject, fetching again anyone with a version not yet known. */
  async #loadKeys(entries: readonly Schemas['LogEntry'][]): Promise<void> {
    const versions = entries.flatMap((entry) => [
      [entry.authorUserId, entry.authorKeyVersion] as const,
      ...(entry.subjectUserId === undefined || entry.subjectKeyVersion === undefined
        ? []
        : [[entry.subjectUserId, entry.subjectKeyVersion] as const]),
    ]);
    await this.#keyring.load(versions.map(([userId]) => userId));
    const unknown = versions
      .filter(([userId, keyVersion]) => this.#keyring.keysOf(userId, keyVersion) === undefined)
      .map(([userId]) => userId);
    if (unknown.length > 0) await this.#keyring.load(unknown, true);
  }

  /** Opens this user's envelope of the current key. */
  async #openEnvelope(
    vaultId: string,
    record: VaultRecord,
    keyVersion: number,
  ): Promise<Uint8Array> {
    const { view } = record;
    if (
      view.keyVersion !== keyVersion ||
      view.keyEnvelope === undefined ||
      view.envelopeUserKeyVersion === undefined
    ) {
      throw new CloakKeyUnavailableError(vaultId, keyVersion);
    }
    const userKeyVersion = view.envelopeUserKeyVersion;
    const privateKey = encryptionKeyFor(this.#self.secrets, this.#self.keyVersion, userKeyVersion);
    if (privateKey === undefined) throw new CloakKeyUnavailableError(vaultId, keyVersion);
    let key: Uint8Array;
    try {
      key = await openEnvelope(
        privateKey,
        vaultId,
        keyVersion,
        { userId: this.#self.userId, userKeyVersion },
        fromBase64Url(view.keyEnvelope),
      );
    } catch (error: unknown) {
      if (isCloakCryptoError(error)) throw new CloakVaultLogError(vaultId, 'key_mismatch');
      throw error;
    }
    return this.#checked(vaultId, record, keyVersion, () => key);
  }

  /** Runs [open] and checks its key against the commitment of [keyVersion]. */
  #checked(
    vaultId: string,
    record: VaultRecord,
    keyVersion: number,
    open: () => Uint8Array,
  ): Uint8Array {
    const committed = record.state.commitments.get(keyVersion);
    try {
      if (committed === undefined) throw new CloakCryptoError('key_mismatch', 'No commitment');
      return requireCommittedKey(open(), vaultId, keyVersion, committed);
    } catch (error: unknown) {
      if (isCloakCryptoError(error)) throw new CloakVaultLogError(vaultId, 'key_mismatch');
      throw error;
    }
  }

  /** A key known to be opened. */
  #required(opened: ReadonlyMap<number, Uint8Array>, version: number): Uint8Array {
    const key = opened.get(version);
    if (key === undefined) throw new RangeError('A vault key that was opened is missing');
    return key;
  }
}
