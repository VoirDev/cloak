import {
  CloakCryptoError,
  deriveLocalRecordKey,
  fromBase64Url,
  isCloakCryptoError,
  openLocalRecord,
  sealLocalRecord,
  toBase64Url,
  type SectionMark,
  type VaultLogState,
} from '@voirdev/cloak-crypto';
import * as z from 'zod';

import { CloakSessionClosedError } from '../CloakSessionClosedError.ts';
import type { CloakStorage } from './CloakStorage.ts';
import { decodeSnapshot, encodeSnapshot, snapshotRecord } from './snapshotCodec.ts';

/** A key version of a person, and its digest. */
export interface KeyVersionRef {
  /** Key version. */
  readonly keyVersion: number;
  /** Its `keysDigest`. */
  readonly keysDigest: Uint8Array;
}

/** The key version of a person this device trusts first (`PROTOCOL.md` §9). */
export interface Pin extends KeyVersionRef {
  /**
   * Whether the pin is vouched for: the user confirmed the person's fingerprint, or a vault the
   * user accepted commits their keys. Only then may the user add them to a vault.
   */
  readonly vouched: boolean;
}

/** What this device signed an acceptance of (`PROTOCOL.md` §15), to sign it again later. */
export interface OwnAcceptances {
  /** Vaults accepted one by one, or created. */
  readonly vaultIds: readonly string[];
  /** People whose every vault the user accepted. */
  readonly inviterUserIds: readonly string[];
}

/** The last entry of a vault log this device verified. */
export interface LogHead {
  /** `seq` of the entry. */
  readonly seq: number;
  /** Its `entryHash`. */
  readonly entryHash: Uint8Array;
}

/** How many buckets a vault's verified sections are spread over, so a change rewrites one. */
export const SECTION_CACHE_BUCKETS = 64;

/** One kept section write: as served, and why it was refused when it was. */
export interface CachedSection {
  /** The write as the server sent it, ciphertext included; checked again when read. */
  readonly write: unknown;
  /** Why it does not stand; absent when it stood at {@link SectionCacheBucket.judgedAt}. */
  readonly refusal?: string | undefined;
}

/** A bucket of a vault's verified sections. */
export interface SectionCacheBucket {
  /** The change number through which the bucket holds every section's latest write. */
  readonly through: number;
  /** The log `seq` against which the standing of its writes was last judged. */
  readonly judgedAt: number;
  /** Writes by `nodeId/sectionName`. */
  readonly sections: Readonly<Record<string, CachedSection>>;
}

/** Where a section lives. */
export interface SectionKey {
  /** Vault. */
  readonly vaultId: string;
  /** Node. */
  readonly nodeId: string;
  /** Section name. */
  readonly sectionName: string;
}

/**
 * What one signed-in user keeps on this device (`PROTOCOL.md` §15): pins, checked host user ids,
 * verified log heads and snapshots, section marks and this device's own writes and entries. Every
 * record is encrypted and bound to its name, so the store can neither read, forge nor move one;
 * deleting one resets it to unseen, and an older copy lowers what the device remembers to that
 * copy. A vault's records share one key prefix, so they are dropped together.
 */
export interface LocalState {
  /** Returns the pin of a person, if this device met them. */
  pin(userId: string): Promise<Pin | undefined>;

  /** Pins a person at a key version. */
  setPin(userId: string, pin: Pin): Promise<void>;

  /** Marks a person's pin vouched for, if it is still the pin of [keysDigest]. */
  vouch(userId: string, keysDigest: Uint8Array): Promise<void>;

  /** Returns the newest key version of a person this device verified a statement for. */
  newest(userId: string): Promise<KeyVersionRef | undefined>;

  /** Remembers a person's newest verified key version, unless a newer one is kept. */
  raiseNewest(userId: string, newest: KeyVersionRef): Promise<void>;

  /** Whether this device last found a vault vouching, having vouched for its members then. */
  vouching(vaultId: string): Promise<boolean>;

  /** Remembers whether a vault vouches (`PROTOCOL.md` §9). */
  setVouching(vaultId: string, vouching: boolean): Promise<void>;

  /** Returns the acceptances this device signed. */
  ownAcceptances(): Promise<OwnAcceptances>;

  /** Remembers an acceptance this device signed, of a vault or of an inviter. */
  addOwnAcceptance(kind: 'vault' | 'inviter', id: string): Promise<void>;

  /** Returns a person's host user id this device checked derives their id (`PROTOCOL.md` §5.0). */
  hostId(userId: string): Promise<string | undefined>;

  /** Remembers a person's host user id, which the caller checked derives their id. */
  setHostId(userId: string, hostUserId: string): Promise<void>;

  /** Returns the newest head this device verified for a vault. */
  head(vaultId: string): Promise<LogHead | undefined>;

  /** Remembers a verified head, unless the one kept is at least as new. */
  advanceHead(vaultId: string, head: LogHead): Promise<void>;

  /** Returns the verified state of a vault's log this device kept (`PROTOCOL.md` §15). */
  snapshot(vaultId: string): Promise<VaultLogState | undefined>;

  /** Keeps a verified state of a vault's log, unless the one kept is at least as long. */
  raiseSnapshot(vaultId: string, state: VaultLogState): Promise<void>;

  /** Returns what this device has seen of a section. */
  mark(section: SectionKey): Promise<SectionMark | undefined>;

  /** Remembers a verified write of a section, unless one at least as new is kept. */
  raiseMark(section: SectionKey, mark: SectionMark): Promise<void>;

  /** Returns the `writeHash` of the latest write this device made to a section. */
  ownWrite(section: SectionKey): Promise<Uint8Array | undefined>;

  /** Remembers a write this device made. */
  setOwnWrite(section: SectionKey, writeHash: Uint8Array): Promise<void>;

  /** Returns the `entryHash` of every log entry this device made in a vault. */
  ownEntries(vaultId: string): Promise<readonly Uint8Array[]>;

  /** Remembers log entries this device made in a vault. */
  addOwnEntries(vaultId: string, entryHashes: readonly Uint8Array[]): Promise<void>;

  /**
   * Returns one bucket of a vault's verified sections (`PROTOCOL.md` §15), if kept.
   *
   * @param vaultId The vault.
   * @param bucket Bucket number, below {@link SECTION_CACHE_BUCKETS}.
   */
  sectionCache(vaultId: string, bucket: number): Promise<SectionCacheBucket | undefined>;

  /**
   * Keeps one bucket of a vault's verified sections. A bucket is whole in itself: its `through`
   * says up to which change it is complete, so an older copy put back only makes the next read
   * fetch more.
   */
  setSectionCache(vaultId: string, bucket: number, value: SectionCacheBucket): Promise<void>;

  /**
   * Drops what this device keeps about a vault (`PROTOCOL.md` §15).
   *
   * @param vaultId The vault.
   * @param keepHead Whether to keep its verified head, so a log shown later must pass through it.
   *   Keep it whenever a signed fact ended the user's membership; drop it only on the user's
   *   say-so, which leaves the device as new for the vault.
   */
  forgetVault(vaultId: string, keepHead: boolean): Promise<void>;

  /** Drops every record of the user on this device, the secret key included. */
  clear(): Promise<void>;

  /**
   * Wipes the record keys, for a closing session. Every later read or write fails, so nothing is
   * ever sealed under a wiped key.
   */
  close(): void;
}

/** Stored form of a key version reference. */
const keyVersionRecord = z.object({
  keyVersion: z.number().int().positive(),
  keysDigest: z.string(),
});

/** Stored form of a pin. */
const pinRecord = keyVersionRecord.extend({ vouched: z.boolean() });

/** Stored form of whether a vault vouches. */
const vouchingRecord = z.object({ vouching: z.boolean() });

/** Stored form of the acceptances this device signed. */
const ownAcceptancesRecord = z.object({
  vaultIds: z.array(z.string()),
  inviterUserIds: z.array(z.string()),
});

/** Stored form of a log head. */
const headRecord = z.object({ seq: z.number().int().positive(), entryHash: z.string() });

/** Stored form of a section mark. */
const markRecord = z.object({ dataVersion: z.number().int().positive(), writeHash: z.string() });

/** Stored form of an own write. */
const ownRecord = z.object({ writeHash: z.string() });

/** Stored form of a vault's own entries. */
const ownEntriesRecord = z.object({ entryHashes: z.array(z.string()) });

/** Stored form of a bucket of verified sections. */
const sectionCacheRecord = z.object({
  through: z.number().int().nonnegative(),
  judgedAt: z.number().int().nonnegative(),
  sections: z.record(z.string(), z.object({ write: z.unknown(), refusal: z.string().optional() })),
});

/** Stored form of a checked host user id. */
const hostIdRecord = z.object({ hostUserId: z.string().min(1) });

/**
 * Key of the record holding a user's secret key. It is stored as raw bytes, outside the local
 * state key, because unlocking needs it before any key exists.
 *
 * @param userId User.
 * @returns Storage key.
 */
export function secretKeyRecord(userId: string): string {
  return `${userRecords(userId)}secret-key`;
}

/**
 * Key prefix of every record of a user on a device, the secret key included.
 *
 * @param userId User.
 * @returns The prefix, ending in `/`.
 */
export function userRecords(userId: string): string {
  return `cloak/v1/${userId}/`;
}

/**
 * Key of the record that tells a user's records were all sealed under the current
 * `localStateKey`; it is itself sealed under that key, and empty.
 */
function movedRecord(userId: string): string {
  return `${userRecords(userId)}moved`;
}

/**
 * Seals every record of a user under the current `localStateKey`, the first time the user unlocks
 * with a bundle that carries a `previousLocalStateKey` (`PROTOCOL.md` §5.4, §12.2): each record
 * still sealed under the previous key is opened with it and sealed again. A record of the moved
 * state is written last, so a move cut short is finished on the next unlock, and once it is there
 * the previous key opens nothing ({@link openLocalState} never takes it). The secret key, kept as
 * is outside the local state key, is left alone.
 *
 * @param storage Where records live.
 * @param userId Signed-in user.
 * @param localStateKey `localStateKey` from the user's bundle.
 * @param previousLocalStateKey The previous version's key, from the same bundle.
 * @throws {CloakCryptoError} `decryption_failed` when a record opens under neither key, because
 *   it was changed or written by someone else; clearing the user's `cloak/v1/<userId>/` records
 *   recovers.
 */
export async function moveLocalState(
  storage: CloakStorage,
  userId: string,
  localStateKey: Uint8Array,
  previousLocalStateKey: Uint8Array,
): Promise<void> {
  const key = deriveLocalRecordKey(localStateKey, userId);
  const previous = deriveLocalRecordKey(previousLocalStateKey, userId);
  try {
    const marker = movedRecord(userId);
    const moved = await storage.get(marker);
    if (moved !== undefined && opens(key, marker, moved)) return;
    for (const name of await storage.keys(userRecords(userId))) {
      if (name === marker || name === secretKeyRecord(userId)) continue;
      const blob = await storage.get(name);
      if (blob === undefined || opens(key, name, blob)) continue;
      const plaintext = openLocalRecord(previous, name, blob);
      await storage.set(name, sealLocalRecord(key, name, plaintext));
      plaintext.fill(0);
    }
    await storage.set(marker, sealLocalRecord(key, marker, new Uint8Array()));
  } finally {
    key.fill(0);
    previous.fill(0);
  }
}

/** Whether a record opens under [key]; any failure but a failed tag stays as it is. */
function opens(key: Uint8Array, name: string, blob: Uint8Array): boolean {
  try {
    openLocalRecord(key, name, blob).fill(0);
    return true;
  } catch (error: unknown) {
    if (isCloakCryptoError(error) && error.code === 'decryption_failed') return false;
    throw error;
  }
}

/**
 * Opens a signed-in user's local state, under the current `localStateKey` alone; after a key
 * replacement, {@link moveLocalState} first moves the records sealed under the previous one.
 *
 * @param storage Where records live.
 * @param userId Signed-in user.
 * @param localStateKey `localStateKey` from the user's bundle.
 * @returns The state.
 * @throws {CloakCryptoError} `decryption_failed` from any read, when a stored record was changed
 *   or written by someone else; clearing the user's `cloak/v1/<userId>/` records recovers.
 */
export function openLocalState(
  storage: CloakStorage,
  userId: string,
  localStateKey: Uint8Array,
): LocalState {
  const key = deriveLocalRecordKey(localStateKey, userId);
  const prefix = userRecords(userId).slice(0, -1);

  /** Whether {@link LocalState.close} wiped the keys. */
  let closed = false;

  /** Opens a blob under the key. */
  function open(name: string, blob: Uint8Array): Uint8Array {
    if (closed) throw new CloakSessionClosedError();
    return openLocalRecord(key, name, blob);
  }

  /** Parses an opened record. */
  function parse<T>(plaintext: Uint8Array, schema: z.ZodType<T>): T {
    const result = schema.safeParse(JSON.parse(new TextDecoder().decode(plaintext)) as unknown);
    if (!result.success)
      throw new CloakCryptoError('invalid_format', 'A local record has an unknown shape');
    return result.data;
  }

  /** Seals a record. */
  function seal(name: string, value: unknown): Uint8Array {
    if (closed) throw new CloakSessionClosedError();
    return sealLocalRecord(key, name, new TextEncoder().encode(JSON.stringify(value)));
  }

  /** Reads a record. */
  async function read<T>(name: string, schema: z.ZodType<T>): Promise<T | undefined> {
    const blob = await storage.get(name);
    return blob === undefined ? undefined : parse(open(name, blob), schema);
  }

  /**
   * Replaces a record with [next] unless [keep] says the stored one wins, atomically when the
   * store supports it.
   */
  function raise<T>(
    name: string,
    schema: z.ZodType<T>,
    next: T,
    keep: (stored: T) => boolean,
  ): Promise<void> {
    return modify(name, schema, (stored) =>
      stored !== undefined && keep(stored) ? undefined : next,
    );
  }

  /** Prefix of a vault's records; ids are UUIDs, so prefixes of two vaults never overlap. */
  function vaultPrefix(vaultId: string): string {
    return `${prefix}/vaults/${vaultId}/`;
  }

  /** Storage name of a section's record, under its vault's prefix. */
  function sectionName(kind: 'mark' | 'own', section: SectionKey): string {
    return `${vaultPrefix(section.vaultId)}${kind}/${section.nodeId}/${section.sectionName}`;
  }

  /** Storage name of a person's record. */
  function personName(kind: 'pin' | 'newest' | 'host-id', userId: string): string {
    return `${prefix}/people/${userId}/${kind}`;
  }

  /** Replaces a record with what [change] makes of the stored one, atomically when supported. */
  async function modify<T>(
    name: string,
    schema: z.ZodType<T>,
    change: (stored: T | undefined) => T | undefined,
  ): Promise<void> {
    const merge = (current: Uint8Array | undefined): Uint8Array | undefined => {
      const next = change(current === undefined ? undefined : parse(open(name, current), schema));
      return next === undefined ? undefined : seal(name, next);
    };
    if (storage.update === undefined) {
      const sealed = merge(await storage.get(name));
      if (sealed !== undefined) await storage.set(name, sealed);
    } else {
      await storage.update(name, merge);
    }
  }

  return {
    async pin(userId) {
      const stored = await read(personName('pin', userId), pinRecord);
      return stored === undefined
        ? undefined
        : {
            keyVersion: stored.keyVersion,
            keysDigest: fromBase64Url(stored.keysDigest),
            vouched: stored.vouched,
          };
    },
    setPin(userId, pin) {
      const name = personName('pin', userId);
      return storage.set(
        name,
        seal(name, {
          keyVersion: pin.keyVersion,
          keysDigest: toBase64Url(pin.keysDigest),
          vouched: pin.vouched,
        }),
      );
    },
    vouch(userId, keysDigest) {
      const digest = toBase64Url(keysDigest);
      return modify(personName('pin', userId), pinRecord, (stored) =>
        stored === undefined || stored.vouched || stored.keysDigest !== digest
          ? undefined
          : { ...stored, vouched: true },
      );
    },
    async newest(userId) {
      const stored = await read(personName('newest', userId), keyVersionRecord);
      return stored === undefined
        ? undefined
        : { keyVersion: stored.keyVersion, keysDigest: fromBase64Url(stored.keysDigest) };
    },
    raiseNewest(userId, newest) {
      return raise(
        personName('newest', userId),
        keyVersionRecord,
        { keyVersion: newest.keyVersion, keysDigest: toBase64Url(newest.keysDigest) },
        (stored) => stored.keyVersion >= newest.keyVersion,
      );
    },
    async vouching(vaultId) {
      return (await read(`${vaultPrefix(vaultId)}vouching`, vouchingRecord))?.vouching ?? false;
    },
    setVouching(vaultId, vouching) {
      const name = `${vaultPrefix(vaultId)}vouching`;
      return storage.set(name, seal(name, { vouching }));
    },
    async ownAcceptances() {
      return (
        (await read(`${prefix}/own-acceptances`, ownAcceptancesRecord)) ?? {
          vaultIds: [],
          inviterUserIds: [],
        }
      );
    },
    addOwnAcceptance(kind, id) {
      return modify(`${prefix}/own-acceptances`, ownAcceptancesRecord, (stored) => {
        const current = stored ?? { vaultIds: [], inviterUserIds: [] };
        const list = kind === 'vault' ? current.vaultIds : current.inviterUserIds;
        if (list.includes(id)) return undefined;
        return kind === 'vault'
          ? { ...current, vaultIds: [...current.vaultIds, id] }
          : { ...current, inviterUserIds: [...current.inviterUserIds, id] };
      });
    },
    async hostId(userId) {
      return (await read(personName('host-id', userId), hostIdRecord))?.hostUserId;
    },
    setHostId(userId, hostUserId) {
      const name = personName('host-id', userId);
      return storage.set(name, seal(name, { hostUserId }));
    },
    async head(vaultId) {
      const stored = await read(`${vaultPrefix(vaultId)}head`, headRecord);
      return stored === undefined
        ? undefined
        : { seq: stored.seq, entryHash: fromBase64Url(stored.entryHash) };
    },
    advanceHead(vaultId, head) {
      return raise(
        `${vaultPrefix(vaultId)}head`,
        headRecord,
        { seq: head.seq, entryHash: toBase64Url(head.entryHash) },
        (stored) => stored.seq >= head.seq,
      );
    },
    async snapshot(vaultId) {
      const stored = await read(`${vaultPrefix(vaultId)}snapshot`, snapshotRecord);
      const state = stored === undefined ? undefined : decodeSnapshot(stored);
      return state?.vaultId === vaultId ? state : undefined;
    },
    raiseSnapshot(vaultId, state) {
      return raise(
        `${vaultPrefix(vaultId)}snapshot`,
        snapshotRecord,
        encodeSnapshot(state),
        (stored) => stored.points.length >= state.points.length,
      );
    },
    async mark(section) {
      const stored = await read(sectionName('mark', section), markRecord);
      return stored === undefined
        ? undefined
        : { dataVersion: stored.dataVersion, writeHash: fromBase64Url(stored.writeHash) };
    },
    raiseMark(section, mark) {
      return raise(
        sectionName('mark', section),
        markRecord,
        { dataVersion: mark.dataVersion, writeHash: toBase64Url(mark.writeHash) },
        (stored) => stored.dataVersion >= mark.dataVersion,
      );
    },
    async ownWrite(section) {
      const stored = await read(sectionName('own', section), ownRecord);
      return stored === undefined ? undefined : fromBase64Url(stored.writeHash);
    },
    async ownEntries(vaultId) {
      const stored = await read(`${vaultPrefix(vaultId)}own-entries`, ownEntriesRecord);
      return (stored?.entryHashes ?? []).map(fromBase64Url);
    },
    async addOwnEntries(vaultId, entryHashes) {
      const name = `${vaultPrefix(vaultId)}own-entries`;
      const added = entryHashes.map(toBase64Url);
      const merge = (current: Uint8Array | undefined): Uint8Array => {
        const stored =
          current === undefined ? [] : parse(open(name, current), ownEntriesRecord).entryHashes;
        return seal(name, { entryHashes: [...new Set([...stored, ...added])] });
      };
      if (storage.update === undefined) await storage.set(name, merge(await storage.get(name)));
      else await storage.update(name, merge);
    },
    setOwnWrite(section, writeHash) {
      const name = sectionName('own', section);
      return storage.set(name, seal(name, { writeHash: toBase64Url(writeHash) }));
    },
    async sectionCache(vaultId, bucket) {
      return read(`${vaultPrefix(vaultId)}cache/${String(bucket)}`, sectionCacheRecord);
    },
    setSectionCache(vaultId, bucket, value) {
      const name = `${vaultPrefix(vaultId)}cache/${String(bucket)}`;
      return storage.set(name, seal(name, value));
    },
    async forgetVault(vaultId, keepHead) {
      const vault = vaultPrefix(vaultId);
      if (!keepHead) {
        await storage.deletePrefix(vault);
        return;
      }
      // Everything but the head, which is never deleted, so a crash midway keeps it too.
      await storage.deletePrefix(`${vault}mark/`);
      await storage.deletePrefix(`${vault}own/`);
      await storage.deletePrefix(`${vault}cache/`);
      await storage.delete(`${vault}snapshot`);
      await storage.delete(`${vault}own-entries`);
      await storage.delete(`${vault}vouching`);
    },
    clear() {
      return storage.deletePrefix(`${prefix}/`);
    },
    close() {
      closed = true;
      key.fill(0);
    },
  };
}
