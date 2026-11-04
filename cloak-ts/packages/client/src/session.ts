import {
  checkpointRoot,
  checkpointsAfter,
  checkSectionOrder,
  cloakUserId,
  encryptSection,
  entryHash,
  headerWriteHash,
  openSectionContent,
  equalBytes,
  fingerprint,
  generateVaultKey,
  keyCommitment,
  keysDigest,
  logHead,
  roleIncludes,
  sealEnvelope,
  signLogEntry,
  signSectionWrite,
  toBase64Url,
  verifySectionStanding,
  wipeIdentitySecrets,
  wrapPreviousKey,
  writeHash,
  type CheckpointLeaf,
  type SectionHeader,
  type LogEntryFields,
  type PublicKeys,
  type Role,
  type SectionWriteFields,
  formatSectionScope,
  identityDeletionMessage,
  nodeIdOf,
  sharedSince,
  signIdentityStatement,
  type NodeOrigin,
  type VaultLogState,
} from '@voirdev/cloak-crypto';

import { CloakAccountNotEmptyError } from './CloakAccountNotEmptyError.ts';
import { CloakApiError, isCloakApiError } from './CloakApiError.ts';
import { originOf } from './nodeRef.ts';
import { createSessionGate } from './sessionGate.ts';
import { CheckpointIndex, queryKey, type CheckpointQuery } from './checkpointIndex.ts';
import { CloakFingerprintRequiredError } from './CloakFingerprintRequiredError.ts';
import { CloakKeyUnavailableError } from './CloakKeyUnavailableError.ts';
import { CloakSectionError, type CloakSectionErrorReason } from './CloakSectionError.ts';
import { CloakVaultLogError } from './CloakVaultLogError.ts';
import { body, noBody, type CloakApi, type Schemas } from './api.ts';
import { decodeContent, encodeContent } from './content.ts';
import type { Keyring } from './keyring.ts';
import type {
  DecryptedNode,
  DecryptedSection,
  KeyReplacementRecord,
  NodeRef,
  Page,
  SectionChange,
  SectionChanges,
  SectionRemoval,
  SectionInfo,
  VaultBatchResult,
  VaultFailure,
  VaultContents,
  VaultSummary,
  VerifiedVault,
} from './model.ts';
import {
  SECTION_CACHE_BUCKETS,
  type LocalState,
  type SectionCacheBucket,
  type SectionKey,
} from './storage/localState.ts';
import { VaultBook, type Self, type VaultRecord } from './vaultBook.ts';
import {
  fromWireHeader,
  fromWireWrite,
  toWireEntry,
  toWireWrite,
  validHeader,
  isFeedRangeSound,
  validHeaderPage,
  validSectionPage,
  validWrite,
} from './wire.ts';

/** An unlocked user: every operation checks what the server returns before using it. */
export interface CloakSession {
  /** The signed-in user's host user id. */
  readonly userId: string;
  /** The user's current identity key version. */
  readonly keyVersion: number;
  /** The user's own fingerprint, for others to confirm. */
  readonly fingerprint: string;
  /** Whether {@link close} was called. */
  readonly closed: boolean;

  /**
   * Ends the session: turns away new operations at once, waits for running ones to end, then
   * wipes the private keys, vault keys and local record keys it holds. Every later call throws
   * `CloakSessionClosedError`; unlock again for a new session. Use it to lock an idle app or on
   * sign-out. The remembered secret key, if any, stays; `forgetSecretKey` removes it.
   *
   * JavaScript keeps no promise that no other copy of a key exists in memory, such as the typed
   * password, copies inside libraries, or what the garbage collector moved: closing shortens how
   * long keys stay, it does not protect against code that can already read the page's memory.
   */
  close(): Promise<void>;

  /**
   * Returns the fingerprint of a person's newest key version this device trusts, pinning them on
   * first use. Compare it with the person out of band.
   */
  fingerprintOf(hostUserId: string): Promise<string>;

  /**
   * Trusts a person at the keys whose fingerprint the user compared with them, so they can be
   * added to vaults (`PROTOCOL.md` §9).
   */
  confirmFingerprint(hostUserId: string, fingerprint: string): Promise<void>;

  /** Lists the vaults the server says the user belongs to; `openVault` verifies each. */
  listVaults(options?: {
    readonly limit?: number;
    readonly cursor?: string;
    /** List the vaults the user was added to and has not accepted instead. */
    readonly pending?: boolean;
  }): Promise<Page<VaultSummary>>;

  /**
   * Accepts a vault the user was added to, so it is listed and the host counts it
   * (`PROTOCOL.md` §12.4). This is the server's help against being added unasked; what the user
   * may read and write in a vault depends on its log alone.
   */
  acceptVault(vaultId: string): Promise<void>;

  /** Accepts every vault one person added the user to, now and later. */
  acceptInvitationsFrom(hostUserId: string): Promise<void>;

  /**
   * Creates a node in its home vault (`PROTOCOL.md` §7.7), owned by the user, who must be an editor
   * or stronger there. Its sections can be written in that vault from then on, and shared by the
   * user into others. Call it only when the user creates the record it holds secrets for, after
   * showing who will read them: the home vault's members. Never create a node because a server or
   * host says a record lives somewhere new.
   *
   * @param homeVaultId The node's home vault.
   * @param nodeKey The application's key for the node, such as the record's id; one other users
   *   cannot choose (`PROTOCOL.md` §7.7).
   * @returns The node, to keep beside the record.
   * @throws {CloakSectionError} `not_shared` when the user has not accepted the home vault.
   */
  createNode(homeVaultId: string, nodeKey: string): Promise<NodeRef>;

  /**
   * Shares sections of the user's node into another vault where the user is an admin
   * (`PROTOCOL.md` §7.7): `*` for every section, which lets that vault's editors add sections the
   * owner never used, or the names to share. Members of that vault then read them; taking them back
   * hides them from then on, but what someone read stays with them.
   */
  shareNode(node: NodeRef, vaultId: string, sections: '*' | readonly string[]): Promise<void>;

  /** Takes back sections of a node shared into a vault; `*` takes back the whole node. */
  unshareNode(node: NodeRef, vaultId: string, sections: '*' | readonly string[]): Promise<void>;

  /** Creates a vault with the user as owner. */
  createVault(): Promise<VerifiedVault>;

  /** Verifies a vault's log and returns what it shows. */
  openVault(vaultId: string): Promise<VerifiedVault>;

  /**
   * Deletes a vault with an owner's signed `vault_deleted` (`PROTOCOL.md` §12.3); the server keeps
   * only its log. This device then forgets it, keeping its verified head.
   */
  deleteVault(vaultId: string): Promise<void>;

  /**
   * Drops what this device keeps about a vault, its verified head included, so the device is as
   * new for it (`PROTOCOL.md` §15). Use it on the user's say-so for a vault the server no longer
   * shows: the device never forgets one on its own, because a server could hide a vault now and
   * show an older history of it later.
   */
  forgetVault(vaultId: string): Promise<void>;

  /**
   * Adds a person with a role, sealing the current key to their newest keys.
   *
   * @throws {CloakFingerprintRequiredError} when this device never met them and their fingerprint
   *   was not confirmed.
   */
  addMember(vaultId: string, hostUserId: string, role: Role): Promise<VerifiedVault>;

  /** Changes a member's role; taking away the right to write carries a checkpoint. */
  setRole(vaultId: string, hostUserId: string, role: Role): Promise<VerifiedVault>;

  /**
   * Gives the vault a new key, removing the given members, and reseals it to everyone else who is
   * not deleted.
   *
   * @param vaultId The vault.
   * @param removeHostIds Members to remove, by host user id.
   * @param options `removeDeleted` also removes every member the server marks deleted
   *   (`PROTOCOL.md` §5.7), including one this device never knew by name. The mark is the server's
   *   word: show it to the admin before they choose this.
   */
  rotate(
    vaultId: string,
    removeHostIds?: readonly string[],
    options?: { readonly removeDeleted?: boolean },
  ): Promise<VerifiedVault>;

  /**
   * Verifies several vaults with as few requests as it can (`PROTOCOL.md` §12.4).
   *
   * @returns Each vault as {@link openVault} returns it, or `undefined` when the user cannot see it.
   */
  openVaults(vaultIds: readonly string[]): Promise<ReadonlyMap<string, VerifiedVault | undefined>>;

  /**
   * Adds a person to several vaults, one by one, such as when sharing a project. A vault where it
   * fails leaves them with less access than asked, never more; the result says which.
   *
   * Pass vaults the user chose: which vaults form a project is the host's record, unsigned, and a
   * server that slipped another vault into it would otherwise get the person added there.
   */
  addMemberToVaults(
    vaultIds: readonly string[],
    hostUserId: string,
    role: Role,
  ): Promise<VaultBatchResult>;

  /**
   * Removes people from up to 100 vaults in one request that the server applies to all of them or
   * to none, rotating each vault's key, so nobody is left half removed. Vaults where none of them
   * is a member are left alone. Pass vaults the user chose, as for {@link addMemberToVaults}.
   *
   * @returns The rotated vaults.
   */
  removeFromVaults(
    vaultIds: readonly string[],
    removeHostIds: readonly string[],
    options?: { readonly removeDeleted?: boolean },
  ): Promise<readonly VerifiedVault[]>;

  /** Leaves a vault; it keeps its key until an admin rotates. This device then forgets it. */
  leave(vaultId: string): Promise<void>;

  /**
   * As an admin, seals the current key to members who replaced their keys since the last rotation
   * and may lack it.
   *
   * @returns How many envelopes were delivered.
   */
  deliverEnvelopes(vaultId: string): Promise<number>;

  /**
   * Records this user's newest keys in a vault (`PROTOCOL.md` §5.6). `replaceKeys` does it in
   * every vault; call it again for a vault where it failed.
   */
  recordKeyReplacement(vaultId: string): Promise<KeyReplacementRecord>;

  /** Reads and checks one section. */
  readSection(vaultId: string, nodeId: string, name: string): Promise<DecryptedSection>;

  /** Reads and checks every section of a node the user can read, across vaults. */
  readNode(nodeId: string): Promise<DecryptedNode>;

  /** Reads and checks a vault's sections whose latest write came after a change number. */
  changes(vaultId: string, afterChange?: number): Promise<SectionChanges>;

  /**
   * Reads every live section of a vault, checked, from what this device keeps and what changed
   * since (`PROTOCOL.md` §15). A write's signature is checked once; its standing is judged again
   * whenever the log adds a checkpoint. Sections the host removed and deleted sections are left
   * out; refused writes are listed with their reason.
   */
  readVault(vaultId: string): Promise<VaultContents>;

  /**
   * Writes one section of a node, in its home vault or in a vault that shares the section's name.
   *
   * @throws {CloakSectionError} `not_shared` when the node does not live in the vault by its
   *   verified log; nothing is encrypted or sent then.
   */
  writeSection(
    vaultId: string,
    node: NodeRef,
    name: string,
    change: { readonly type: string; readonly content: unknown },
  ): Promise<SectionInfo>;

  /** Deletes one section; a deletion may go wherever the user may write. */
  deleteSection(vaultId: string, node: NodeRef, name: string, type: string): Promise<SectionInfo>;

  /**
   * Deletes the user's account (`PROTOCOL.md` §5.7): deletes every vault where the user is the
   * only member who is not deleted, leaves every other one, deletes the identity and clears
   * everything this device keeps for the user, the secret key included. The session is unusable
   * afterwards.
   *
   * Nothing is changed while the user is the only owner of a vault that has other members. Vaults
   * the user never accepted are not left: they do not hold the deletion up (`PROTOCOL.md` §5.7).
   *
   * @throws {CloakAccountNotEmptyError} naming those vaults; appoint another owner first.
   */
  deleteAccount(): Promise<void>;

  /**
   * Writes up to 100 sections in any of the user's vaults, together or not at all. The request
   * must fit the server's `maxRequestBytes` (`GET /meta`); a larger one fails with
   * `payload_too_large`, and nothing is written.
   */
  writeSections(changes: readonly SectionChange[]): Promise<readonly SectionInfo[]>;

  /**
   * Moves a section to another vault where its node lives: a deletion and a first write in one
   * batch.
   */
  moveSection(
    node: NodeRef,
    name: string,
    fromVaultId: string,
    toVaultId: string,
  ): Promise<SectionInfo>;
}

/** What a session needs. */
export interface SessionContext {
  /** HTTP client. */
  readonly api: CloakApi;
  /** Local state. */
  readonly local: LocalState;
  /** Trusted keys. */
  readonly keyring: Keyring;
  /** The user, with their current public keys. */
  readonly self: Self & { readonly keys: PublicKeys };
}

/** Entries a change signed, kept as this device's own once the server accepts them. */
type OwnEntries = { vaultId: string; hash: Uint8Array }[];

/** How long a signed identity deletion stays valid (`PROTOCOL.md` §5.7), in seconds. */
const DELETION_WINDOW_SECONDS = 300;

/** How many times a write is redone after another device moved the log or rotated the key. */
const RETRIES = 3;

/**
 * How many times a checkpoint is built again after writes slipped in. Each retry reads only the
 * headers written since, so it is quick, and a busy vault gets more tries.
 */
const CHECKPOINT_RETRIES = 6;

/** Headers per page when a checkpoint's author lists a vault: the API's index page size. */
const HEADER_PAGE = 1000;

/** A served write's header, as sent and as decoded. */
interface ServedHeader {
  /** As the server sent it. */
  readonly wire: Schemas['SectionHeader'];
  /** Decoded. */
  readonly header: SectionHeader;
  /** Whether this device verified its signature before, as for a write it keeps (§15). */
  readonly signatureVerified?: boolean;
}

/** Whether a write stands (`PROTOCOL.md` §8.4), with its `writeHash`, or why not. */
type Standing =
  | { readonly ok: true; readonly writeHash: Uint8Array }
  | { readonly ok: false; readonly reason: CloakSectionErrorReason };

/**
 * What a checkpoint's author has judged of a vault's latest writes, so a retry after a
 * `checkpoint_conflict` reads only the headers written since. Valid while the log head is the same.
 */
interface CheckpointDraft {
  /** Head of the log the writes were judged against. */
  readonly logSeq: number;
  /** Change number the headers were read up to. */
  lastChange: number;
  /** The latest write of each section with its standing, by section. */
  readonly writes: Map<string, { readonly served: ServedHeader; readonly standing: Standing }>;
}

/**
 * Creates a session.
 *
 * @param context HTTP client, local state, keyring and the user's keys.
 * @returns The session.
 */
export function createSession(context: SessionContext): CloakSession {
  const { api, local, keyring, self } = context;
  const book = new VaultBook(api, keyring, local, self);
  const index = new CheckpointIndex(api);
  /** The latest change number this session read for each vault. */
  const seenChange = new Map<string, number>();
  /** Checkpoint drafts by vault. */
  const drafts = new Map<string, CheckpointDraft>();
  /** Vaults whose writes this session paused and the server may still hold paused. */
  const paused = new Set<string>();

  /**
   * Drops what this session and this device keep about a vault (`PROTOCOL.md` §15).
   *
   * @param vaultId The vault.
   * @param keepHead Whether the device keeps the verified head; see {@link LocalState.forgetVault}.
   */
  async function forget(vaultId: string, keepHead: boolean): Promise<void> {
    book.forget(vaultId);
    seenChange.delete(vaultId);
    drafts.delete(vaultId);
    await local.forgetVault(vaultId, keepHead);
  }

  /**
   * A member's host user id. Every member's keys are loaded and checked when their log entries
   * verify, so only a deleted member this device never knew by name lacks one; any other member
   * without one means the vault was not verified.
   */
  function hostIdOf(vaultId: string, userId: string): string | undefined {
    const hostUserId = keyring.hostIdOf(userId);
    if (hostUserId === undefined && !keyring.isDeleted(userId))
      throw new CloakVaultLogError(vaultId, 'state_mismatch');
    return hostUserId;
  }

  /** The public view of a verified vault. */
  function toVerified(vaultId: string, record: VaultRecord): VerifiedVault {
    const head = logHead(record.state);
    const { members, sinceRotation } = record.state;
    const me = members.get(self.userId);
    if (me === undefined) throw new CloakVaultLogError(vaultId, 'state_mismatch');
    const rotationDue = sinceRotation.departed.length > 0 || sinceRotation.replacedKeys.length > 0;
    return {
      deleted: record.state.deleted,
      id: vaultId,
      role: me.role,
      keyVersion: head.keyVersion,
      logSeq: head.seq,
      members: [...members].map(([userId, member]) => ({
        userId: hostIdOf(vaultId, userId),
        role: member.role,
        keyVersion: member.keyVersion,
        keysCurrent: !keyring.isSuperseded(userId, member.keyVersion),
        deleted: keyring.isDeleted(userId),
      })),
      rotationDue,
    };
  }

  /** Entry fields at [seq] after [previousHash], authored by this user. */
  function entryFields(
    record: VaultRecord,
    fields: Omit<
      LogEntryFields,
      'vaultId' | 'seq' | 'previousHash' | 'authorUserId' | 'authorKeyVersion'
    >,
    seq: number,
    previousHash: Uint8Array,
  ): LogEntryFields {
    return {
      ...fields,
      vaultId: record.view.id,
      seq,
      previousHash,
      authorUserId: self.userId,
      authorKeyVersion: self.keyVersion,
    };
  }

  /** One signed entry that continues the head of [record]. */
  function nextEntry(
    record: VaultRecord,
    own: OwnEntries,
    fields: Omit<
      LogEntryFields,
      'vaultId' | 'seq' | 'previousHash' | 'authorUserId' | 'authorKeyVersion'
    >,
  ): Schemas['LogEntryInput'] {
    const head = logHead(record.state);
    return signEntry(entryFields(record, fields, head.seq + 1, head.hash), own);
  }

  /** Signs entry fields, noting the entry in [own] to keep once the server accepts it. */
  function signEntry(fields: LogEntryFields, own: OwnEntries): Schemas['LogEntryInput'] {
    own.push({ vaultId: fields.vaultId, hash: entryHash(fields) });
    return toWireEntry(fields, signLogEntry(fields, self.secrets.signingSeed));
  }

  /** The member's committed keys in [record], or fails. */
  function committed(
    vaultId: string,
    record: VaultRecord,
    userId: string,
  ): { readonly role: Role; readonly keyVersion: number; readonly keysDigest: Uint8Array } {
    const member = record.state.members.get(userId);
    if (member === undefined) throw new CloakVaultLogError(vaultId, 'state_mismatch');
    return member;
  }

  /** Reads one page of a vault's sections in change order. */
  async function feed(vaultId: string, afterChange: number): Promise<Schemas['SectionPage']> {
    const page = validSectionPage(
      await body(
        api.GET('/vaults/{vaultId}/sections', {
          params: {
            path: { vaultId },
            query: { ...(afterChange === 0 ? {} : { afterChange }), limit: 100 },
          },
        }),
      ),
    );
    if (!isFeedRangeSound(page, afterChange))
      throw new CloakVaultLogError(vaultId, 'state_mismatch');
    seenChange.set(vaultId, page.lastChangeSeq);
    return page;
  }

  /** Reads one page of a vault's section headers in change order. */
  async function headerFeed(
    vaultId: string,
    afterChange: number,
    limit = HEADER_PAGE,
  ): Promise<Schemas['SectionHeaderPage']> {
    const page = validHeaderPage(
      await body(
        api.GET('/vaults/{vaultId}/section-headers', {
          params: {
            path: { vaultId },
            query: { ...(afterChange === 0 ? {} : { afterChange }), limit },
          },
        }),
      ),
    );
    if (!isFeedRangeSound(page, afterChange))
      throw new CloakVaultLogError(vaultId, 'state_mismatch');
    seenChange.set(vaultId, page.lastChangeSeq);
    return page;
  }

  /**
   * Refuses served writes that are not where they were asked for, or that name one section twice:
   * a server could otherwise answer one read with another, validly signed section.
   */
  function requirePlace(
    vaultId: string,
    writes: readonly Schemas['SectionHeader'][],
    place: { readonly vaultId?: string; readonly nodeId?: string; readonly sectionName?: string },
  ): void {
    const seen = new Set<string>();
    for (const write of writes) {
      const valid = validHeader(write);
      const address = `${valid.vaultId}/${valid.nodeId}/${valid.sectionName}`;
      if (
        (place.vaultId !== undefined && valid.vaultId !== place.vaultId) ||
        (place.nodeId !== undefined && valid.nodeId !== place.nodeId) ||
        (place.sectionName !== undefined && valid.sectionName !== place.sectionName) ||
        seen.has(address)
      ) {
        throw new CloakVaultLogError(vaultId, 'state_mismatch');
      }
      seen.add(address);
    }
  }

  /**
   * Judges the standing of served writes of one vault (`PROTOCOL.md` §8.4) and this device's
   * marks (§15), all at once: one key load for every writer, one checkpoint lookup for every
   * write. Marks rise for each write that stands.
   */
  async function judge(vaultId: string, served: readonly ServedHeader[]): Promise<Standing[]> {
    if (served.length === 0) return [];
    let record = await book.verify(vaultId, false);
    const newest = Math.max(...served.map(({ header }) => header.logSeq));
    if (newest > logHead(record.state).seq) record = await book.verify(vaultId);
    const { state } = record;
    await keyring.load([...new Set(served.map(({ header }) => header.writerUserId))]);

    const queries: CheckpointQuery[] = [];
    for (const { header } of served) {
      const { first, latest } = checkpointsAfter(state, header.logSeq);
      for (const checkpoint of new Set([first, latest])) {
        if (checkpoint !== undefined)
          queries.push({ checkpoint, nodeId: header.nodeId, sectionName: header.sectionName });
      }
    }
    const answers = await index.lookup(vaultId, queries);

    const verdicts: Standing[] = [];
    for (const { header } of served) {
      const key: SectionKey = {
        vaultId,
        nodeId: header.nodeId,
        sectionName: header.sectionName,
      };
      const { first, latest } = checkpointsAfter(state, header.logSeq);
      const checkpointLeaves = new Map<number, CheckpointLeaf | undefined>();
      for (const checkpoint of [first, latest]) {
        if (checkpoint !== undefined)
          checkpointLeaves.set(
            checkpoint.seq,
            answers.get(queryKey(checkpoint.seq, header.nodeId, header.sectionName)),
          );
      }
      const mark = await local.mark(key);
      // Rule 4 covers every write this device had not verified before (`PROTOCOL.md` §7.6, §8.4);
      // the section's mark tells whether it verified this very write.
      const seenBefore = mark !== undefined && equalBytes(mark.writeHash, headerWriteHash(header));
      const result = verifySectionStanding(header, state, {
        keysOf: (userId, keyVersion) => keyring.keysOf(userId, keyVersion),
        isSuperseded: seenBefore
          ? undefined
          : (userId, keyVersion) =>
              book.isSuperseded(state.recordedKeyVersions, userId, keyVersion),
        checkpointLeaves,
        signatureVerified: served[verdicts.length]?.signatureVerified,
      });
      if (!result.ok) {
        verdicts.push(result);
        continue;
      }
      const order = checkSectionOrder(mark, {
        dataVersion: header.dataVersion,
        previousWriteHash: header.previousWriteHash,
        writeHash: result.writeHash,
      });
      if (order !== undefined) {
        verdicts.push({ ok: false, reason: order });
        continue;
      }
      await local.raiseMark(key, { dataVersion: header.dataVersion, writeHash: result.writeHash });
      verdicts.push(result);
    }
    return verdicts;
  }

  /** Reads and checks served writes of one vault: their standing, then their content. */
  async function readWrites(
    vaultId: string,
    wires: readonly Schemas['SectionWrite'][],
    verified: ReadonlySet<string> = new Set(),
  ): Promise<DecryptedSection[]> {
    const decoded = wires.map((wire) => ({ wire, opened: fromWireWrite(wire) }));
    const judged = decoded.flatMap(({ wire, opened }) =>
      opened === undefined
        ? []
        : [{ wire, header: opened.header, signatureVerified: verified.has(wire.writeHash) }],
    );
    const verdicts = await judge(vaultId, judged);
    const record = await book.verify(vaultId, false);
    const sections: DecryptedSection[] = [];
    let judgedIndex = 0;
    for (const { wire, opened } of decoded) {
      const info = sectionInfo(wire);
      if (opened === undefined) {
        sections.push({ ...info, status: 'refused', reason: 'bad_ciphertext' });
        continue;
      }
      const standing = verdicts[judgedIndex];
      judgedIndex += 1;
      if (standing === undefined) throw new RangeError('A write was not judged');
      if (!standing.ok) {
        sections.push({ ...info, status: 'refused', reason: standing.reason });
        continue;
      }
      const { write, header } = opened;
      const vaultKey = write.deleted ? undefined : await book.key(vaultId, write.vaultKeyVersion);
      const content = openSectionContent(write, record.state, vaultKey, header.ciphertextHash);
      if (!content.ok) sections.push({ ...info, status: 'refused', reason: content.reason });
      else if (content.content === undefined) sections.push({ ...info, status: 'deleted' });
      else sections.push({ ...info, status: 'ok', content: decodeContent(content.content) });
    }
    return sections;
  }

  /**
   * A checkpoint over the vault's latest writes that stand (`PROTOCOL.md` §7.5, §8.4); with
   * [replacedBelow], writes this user signed with older keys that this device did not make are
   * left out too. It reads headers, never ciphertext, and keeps what it judged: built again after
   * a `checkpoint_conflict` on the same head, it reads only the headers written since.
   */
  /**
   * Brings a vault's checkpoint draft up to the server's latest change: reads only the headers
   * written since the draft last read, judges them, and drops sections the host removed. The
   * draft lives as long as the log head it was judged against.
   */
  async function readDraft(vaultId: string): Promise<CheckpointDraft> {
    const head = logHead((await book.verify(vaultId, false)).state).seq;
    let draft = drafts.get(vaultId);
    if (draft?.logSeq !== head) {
      draft = { logSeq: head, lastChange: 0, writes: new Map() };
      drafts.set(vaultId, draft);
    }
    for (;;) {
      const page = await headerFeed(vaultId, draft.lastChange);
      requirePlace(vaultId, page.items, { vaultId });
      const served = page.items.map((wire) => ({ wire, header: fromWireHeader(wire) }));
      const verdicts = await judge(vaultId, served);
      served.forEach((item, position) => {
        const standing = verdicts[position];
        if (standing === undefined) throw new RangeError('A write was not judged');
        draft.writes.set(`${item.wire.nodeId}/${item.wire.sectionName}`, {
          served: item,
          standing,
        });
      });
      for (const removal of page.removed)
        draft.writes.delete(`${removal.nodeId}/${removal.sectionName}`);
      draft.lastChange = page.throughChangeSeq;
      if (page.throughChangeSeq >= page.lastChangeSeq) return draft;
    }
  }

  /**
   * Asks the server to pause section writes to vaults while this session finishes their
   * checkpoints (`PROTOCOL.md` §7.5). The pause is the server's help against a member who keeps
   * writing, not something the checkpoint relies on, so a refusal only means building without it.
   *
   * @returns Whether the pause was granted.
   */
  async function pauseWrites(vaultIds: readonly string[]): Promise<boolean> {
    try {
      await body(api.POST('/write-pauses', { body: { vaultIds: [...vaultIds] } }));
      for (const vaultId of vaultIds) paused.add(vaultId);
      return true;
    } catch (error: unknown) {
      if (error instanceof CloakApiError) return false;
      throw error;
    }
  }

  /**
   * Ends this session's pauses of vaults whose checkpointed request did not go through; the
   * server ends the others itself when it applies the request. Failing to release only lets a
   * pause run out on its own.
   */
  async function releasePauses(vaultIds: readonly string[]): Promise<void> {
    const held = vaultIds.filter((vaultId) => paused.has(vaultId));
    if (held.length === 0) return;
    for (const vaultId of held) paused.delete(vaultId);
    try {
      await noBody(api.POST('/write-pauses/release', { body: { vaultIds: held } }));
    } catch (error: unknown) {
      if (!(error instanceof CloakApiError)) throw error;
    }
  }

  /**
   * The checkpoint of a vault's draft (`PROTOCOL.md` §7.5): every live section's latest write
   * that stands is a leaf; one that does not stand, or that the user's replaced keys signed
   * without this device, is left out. A deletion is never a leaf and never left out.
   */
  async function checkpointOf(vaultId: string, draft: CheckpointDraft, replacedBelow?: number) {
    const leaves: CheckpointLeaf[] = [];
    const leftOut: Schemas['LeftOutWrite'][] = [];
    for (const { served, standing } of draft.writes.values()) {
      const { wire, header } = served;
      if (header.deleted) continue;
      const hash = headerWriteHash(header);
      const key: SectionKey = { vaultId, nodeId: wire.nodeId, sectionName: wire.sectionName };
      const stolen =
        replacedBelow !== undefined &&
        wire.writerUserId === self.userId &&
        wire.writerKeyVersion < replacedBelow &&
        !equalBytes((await local.ownWrite(key)) ?? new Uint8Array(), hash);
      if (!standing.ok || stolen) {
        leftOut.push({
          nodeId: wire.nodeId,
          sectionName: wire.sectionName,
          writeHash: toBase64Url(hash),
        });
      } else {
        leaves.push({
          nodeId: wire.nodeId,
          sectionName: wire.sectionName,
          dataVersion: wire.dataVersion,
          writeHash: hash,
        });
      }
    }
    return { root: checkpointRoot(leaves), leftOut };
  }

  /**
   * Builds the checkpoints of vaults for one request: drafts them without a pause, which may take
   * long, then pauses writes to all of them at once and reads only what slipped in since.
   */
  async function buildCheckpoints(vaultIds: readonly string[], replacedBelow?: number) {
    for (const vaultId of vaultIds) await readDraft(vaultId);
    await pauseWrites(vaultIds);
    const checkpoints = new Map<string, Awaited<ReturnType<typeof checkpointOf>>>();
    for (const vaultId of vaultIds) {
      checkpoints.set(
        vaultId,
        await checkpointOf(vaultId, await readDraft(vaultId), replacedBelow),
      );
    }
    return checkpoints;
  }

  /** The checkpoint of one vault; see {@link buildCheckpoints}. */
  async function buildCheckpoint(vaultId: string, replacedBelow?: number) {
    const checkpoint = (await buildCheckpoints([vaultId], replacedBelow)).get(vaultId);
    if (checkpoint === undefined) throw new RangeError('No checkpoint was built');
    return checkpoint;
  }

  /**
   * Where a vault stands. The verified head and key version come from the signed log, so a
   * server cannot fake a move; the latest change number is only the server's word, so it counts
   * only for `checkpoint_conflict`, which a new section write causes without moving the log.
   */
  function positionOf(
    vaultId: string,
    record: VaultRecord | undefined,
    withChanges: boolean,
  ): string {
    const head = record === undefined ? undefined : logHead(record.state);
    const changes = withChanges ? `/${String(seenChange.get(vaultId))}` : '';
    return `${String(head?.seq)}/${String(head?.keyVersion)}${changes}`;
  }

  /**
   * Runs a change against fresh state, redoing it when another device moved the vaults first.
   * Before signing again, it checks that a vault really moved: otherwise a server could claim
   * conflicts to collect several validly signed versions of one change. Entries the change
   * signed are kept as this device's own once the server accepted them.
   */
  async function retrying<T>(
    vaultIds: readonly string[],
    change: (own: OwnEntries) => Promise<T>,
  ): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      const own: OwnEntries = [];
      try {
        const result = await change(own);
        // The server ends a pause when it applies the request that carried the checkpoint.
        for (const vaultId of vaultIds) paused.delete(vaultId);
        await keepOwn(own);
        return result;
      } catch (error: unknown) {
        const stale = [
          'log_conflict',
          'stale_head',
          'checkpoint_conflict',
          'vault_key_version_mismatch',
        ].some((code) => isCloakApiError(error, code));
        const withChanges = isCloakApiError(error, 'checkpoint_conflict');
        if (!stale || attempt >= (withChanges ? CHECKPOINT_RETRIES : RETRIES)) {
          await releasePauses(vaultIds);
          throw error;
        }
        let moved = false;
        for (const vaultId of vaultIds) {
          const before = positionOf(vaultId, await book.verify(vaultId, false), withChanges);
          const record = await book.verify(vaultId);
          if (withChanges) await headerFeed(vaultId, seenChange.get(vaultId) ?? 0, 1);
          if (positionOf(vaultId, record, withChanges) !== before) moved = true;
        }
        if (!moved) {
          await releasePauses(vaultIds);
          throw error;
        }
      }
    }
  }

  /** Keeps entries the server accepted as this device's own. */
  async function keepOwn(own: OwnEntries): Promise<void> {
    for (const vaultId of new Set(own.map((entry) => entry.vaultId))) {
      await local.addOwnEntries(
        vaultId,
        own.filter((entry) => entry.vaultId === vaultId).map((entry) => entry.hash),
      );
    }
  }

  /**
   * Entries of a vault signed with this user's replaced keys that this device never signed
   * (`PROTOCOL.md` §5.6): what a thief of the old keys, or another device of the user, did.
   */
  async function unrecognized(vaultId: string, record: VaultRecord): Promise<number[]> {
    const mine = new Set((await local.ownEntries(vaultId)).map((hash) => toBase64Url(hash)));
    return record.state.points
      .filter(
        (point) =>
          point.authorUserId === self.userId &&
          point.authorKeyVersion < self.keyVersion &&
          !mine.has(toBase64Url(point.hash)),
      )
      .map((point) => point.seq);
  }

  /** Verifies a vault again and returns its public view. */
  /**
   * Reads a vault through this device's verified section cache (`PROTOCOL.md` §15). Every bucket
   * says through which change it is complete, so the feed is read from the least complete one,
   * and a bucket put back from an older copy only means reading more. A kept write whose standing
   * the log could have changed since, because a checkpoint came after it was judged, is judged
   * again without its signature; new writes are judged in full.
   *
   * @param vaultId The vault.
   * @param mayRetry Whether a cache that no longer parses may be dropped and the read done again.
   */
  async function readVault(vaultId: string, mayRetry: boolean): Promise<VaultContents> {
    const record = await book.verify(vaultId);
    const head = logHead(record.state).seq;
    const buckets: SectionCacheBucket[] = [];
    for (let bucket = 0; bucket < SECTION_CACHE_BUCKETS; bucket += 1)
      buckets.push(
        (await local.sectionCache(vaultId, bucket)) ?? { through: 0, judgedAt: 0, sections: {} },
      );
    const kept = buckets.map((bucket) => new Map(Object.entries(bucket.sections)));
    const dirty = new Set<number>();

    let after = Math.min(...buckets.map((bucket) => bucket.through));
    const fresh = new Map<string, Schemas['SectionWrite']>();
    let page: Schemas['SectionPage'];
    do {
      page = await feed(vaultId, after);
      requirePlace(vaultId, page.items, { vaultId });
      // Writes and removals apply in change order, so the later of the two wins.
      const events = [
        ...page.items.map((item) => ({ changeSeq: item.changeSeq, item, removal: undefined })),
        ...page.removed.map((removal) => ({
          changeSeq: removal.changeSeq,
          item: undefined,
          removal,
        })),
      ].sort((a, b) => a.changeSeq - b.changeSeq);
      for (const { item, removal } of events) {
        if (item !== undefined) {
          fresh.set(`${item.nodeId}/${item.sectionName}`, item);
          continue;
        }
        const key = `${removal.nodeId}/${removal.sectionName}`;
        fresh.delete(key);
        const bucket = bucketOf(key);
        if (kept[bucket]?.delete(key) === true) dirty.add(bucket);
      }
      after = page.throughChangeSeq;
    } while (page.throughChangeSeq < page.lastChangeSeq);
    const { lastChangeSeq } = page;

    // What to judge: new writes in full, kept ones only when a checkpoint came since they were.
    const toRead: Schemas['SectionWrite'][] = [];
    const verified = new Set<string>();
    const settled: DecryptedSection[] = [];
    for (const [bucket, sections] of kept.entries()) {
      const judgedAt = buckets[bucket]?.judgedAt ?? 0;
      // A new checkpoint, or a change to where nodes live, can make a kept write stop standing.
      const rejudge =
        record.state.placesChangedAt > judgedAt ||
        record.state.checkpoints.some((checkpoint) => checkpoint.seq > judgedAt);
      for (const [key, cached] of sections) {
        if (fresh.has(key)) continue;
        let write: Schemas['SectionWrite'];
        try {
          write = validWrite(cached.write);
        } catch {
          if (!mayRetry) throw new CloakVaultLogError(vaultId, 'state_mismatch');
          await local.forgetVault(vaultId, true);
          return readVault(vaultId, false);
        }
        if (cached.refusal !== undefined) {
          // The reason was stored by this device from a verdict, in a record only it can seal.
          const reason = cached.refusal as CloakSectionErrorReason;
          settled.push({ ...sectionInfo(write), status: 'refused', reason });
          continue;
        }
        if (rejudge) dirty.add(bucket);
        verified.add(write.writeHash);
        toRead.push(write);
      }
    }
    for (const [key, write] of fresh) {
      dirty.add(bucketOf(key));
      toRead.push(write);
    }

    const read = await readWrites(vaultId, toRead, verified);
    const sections: DecryptedSection[] = [...settled];
    read.forEach((section, position) => {
      const write = toRead[position];
      if (write === undefined) throw new RangeError('A write was not read');
      const key = `${write.nodeId}/${write.sectionName}`;
      const bucket = bucketOf(key);
      if (section.status === 'deleted') {
        if (kept[bucket]?.delete(key) === true) dirty.add(bucket);
        return;
      }
      // Every write read here is new or judged again, so its bucket is already marked dirty.
      kept[bucket]?.set(
        key,
        section.status === 'refused' ? { write, refusal: section.reason } : { write },
      );
      sections.push(section);
    });

    for (const [bucket, sectionsOf] of kept.entries()) {
      const stored = buckets[bucket];
      if (stored?.through === lastChangeSeq && stored.judgedAt === head && !dirty.has(bucket))
        continue;
      await local.setSectionCache(vaultId, bucket, {
        through: lastChangeSeq,
        judgedAt: head,
        sections: Object.fromEntries(sectionsOf),
      });
    }
    return {
      sections: sections.sort((a, b) => a.changeSeq - b.changeSeq),
      lastChangeSeq,
    };
  }

  /** What every read section reports about itself, from its write. */
  function sectionInfo(wire: Schemas['SectionWrite']): SectionInfo {
    return {
      vaultId: wire.vaultId,
      nodeId: wire.nodeId,
      name: wire.sectionName,
      type: wire.nodeType,
      dataVersion: wire.dataVersion,
      changeSeq: wire.changeSeq,
      writerUserId: keyring.hostIdOf(wire.writerUserId) ?? wire.writerUserId,
      node: {
        owner: keyring.hostIdOf(wire.ownerUserId) ?? wire.ownerUserId,
        home: wire.homeVaultId,
        key: wire.nodeKey,
      },
    };
  }

  /**
   * Appends one node entry (`PROTOCOL.md` §7.7) to a vault, built against its verified log: none
   * when [build] finds nothing to do, such as a node already created.
   */
  async function nodeEntry(
    vaultId: string,
    build: (
      record: VaultRecord,
    ) =>
      Pick<LogEntryFields, 'kind' | 'nodeId' | 'homeVaultId' | 'nodeKey' | 'sections'> | undefined,
  ): Promise<void> {
    await retrying([vaultId], async (own) => {
      const record = await book.verify(vaultId);
      const fields = build(record);
      if (fields === undefined) return;
      const log = nextEntry(record, own, {
        ...fields,
        keyVersion: logHead(record.state).keyVersion,
        requestEnd: true,
      });
      await body(
        api.POST('/vaults/{vaultId}/node-entries', {
          params: { path: { vaultId } },
          body: { log },
        }),
      );
    });
  }

  /**
   * The body of a rotation request (`PROTOCOL.md` §7.4): removals of the named members, and of
   * every member the server marks deleted when asked, then `key_rotated` with the checkpoint, and
   * the new key sealed to every remaining member whose keys are current and who is not deleted.
   * Members' keys must have been loaded afresh.
   */
  async function rotationOf(
    vaultId: string,
    record: VaultRecord,
    named: readonly string[],
    options: { readonly removeDeleted?: boolean },
    checkpoint: { readonly root: Uint8Array; readonly leftOut: readonly Schemas['LeftOutWrite'][] },
    own: OwnEntries,
  ): Promise<Schemas['RotateVaultRequest']> {
    const remove = [
      ...new Set([
        ...named.filter((userId) => record.state.members.has(userId)),
        ...(options.removeDeleted === true
          ? [...record.state.members.keys()].filter(
              (userId) => userId !== self.userId && keyring.isDeleted(userId),
            )
          : []),
      ]),
    ];
    const head = logHead(record.state);
    const current = await book.key(vaultId, head.keyVersion);
    const next = generateVaultKey();
    const nextVersion = head.keyVersion + 1;
    const entries: Schemas['LogEntryInput'][] = [];
    let seq = head.seq;
    let previousHash = head.hash;
    for (const userId of remove) {
      const member = committed(vaultId, record, userId);
      const fields = entryFields(
        record,
        {
          kind: 'member_removed',
          subjectUserId: userId,
          keyVersion: head.keyVersion,
          subjectKeys: member.keysDigest,
          subjectKeyVersion: member.keyVersion,
          requestEnd: false,
        },
        seq + 1,
        previousHash,
      );
      entries.push(signEntry(fields, own));
      seq += 1;
      previousHash = entryHash(fields);
    }
    const rotated = entryFields(
      record,
      {
        kind: 'key_rotated',
        keyVersion: nextVersion,
        keyCommitment: keyCommitment(next, vaultId, nextVersion),
        checkpoint: checkpoint.root,
        requestEnd: true,
      },
      seq + 1,
      previousHash,
    );
    entries.push(signEntry(rotated, own));
    const envelopes = [];
    for (const [userId, member] of record.state.members) {
      if (remove.includes(userId)) continue;
      // Neither superseded keys nor a deleted person's get the new key (§6.3).
      if (keyring.isSuperseded(userId, member.keyVersion) || keyring.isDeleted(userId)) continue;
      const keys = keyring.keysOf(userId, member.keyVersion);
      if (keys === undefined) throw new CloakVaultLogError(vaultId, 'unverified_keys');
      const envelope = await sealEnvelope(
        keys.encryptionPublicKey,
        vaultId,
        nextVersion,
        { userId, userKeyVersion: member.keyVersion },
        next,
      );
      envelopes.push({
        userId,
        userKeyVersion: member.keyVersion,
        keyEnvelope: toBase64Url(envelope),
      });
    }
    return {
      keyVersion: nextVersion,
      previousWrappedKey: toBase64Url(wrapPreviousKey(next, vaultId, nextVersion, current)),
      envelopes,
      log: entries,
      ...(checkpoint.leftOut.length === 0 ? {} : { leftOut: [...checkpoint.leftOut] }),
    };
  }

  /** The refusal for a vault the user cannot see, as the server itself answers. */
  function notVisible(vaultId: string): CloakApiError {
    return new CloakApiError(404, {
      code: 'not_found',
      detail: 'The vault is not visible.',
      vaultId,
    });
  }

  async function reopen(vaultId: string): Promise<VerifiedVault> {
    const verified = toVerified(vaultId, await book.verify(vaultId));
    // A signed deletion is a fact this device may forget the vault on (§15).
    if (verified.deleted) await forget(vaultId, true);
    return verified;
  }

  /** Signs one write of [change] against fresh state. */
  async function prepare(
    change: SectionChange,
    fresh: Map<string, VaultRecord>,
  ): Promise<{ readonly wire: Schemas['SectionWriteInput']; readonly fields: SectionWriteFields }> {
    const record = fresh.get(change.vaultId) ?? (await book.verify(change.vaultId));
    fresh.set(change.vaultId, record);
    const head = logHead(record.state);
    const origin = originOf(change.node);
    const nodeId = nodeIdOf(origin);
    const deleted = change.content === undefined;
    // Rule 6 before anything is encrypted: content goes only where the owner put the node, whatever
    // the application or the server says (§8.3). A deletion carries nothing to read.
    if (!deleted && !livesIn(record.state, change.vaultId, nodeId, origin, change.name)) {
      throw new CloakSectionError(change.vaultId, nodeId, change.name, 'not_shared');
    }
    const latest = await body(
      api.GET('/vaults/{vaultId}/sections/{nodeId}/{sectionName}', {
        params: {
          path: { vaultId: change.vaultId, nodeId, sectionName: change.name },
        },
      }),
    ).catch((error: unknown) => {
      if (isCloakApiError(error, 'not_found')) return undefined;
      throw error;
    });
    if (latest !== undefined)
      requirePlace(change.vaultId, [latest], {
        vaultId: change.vaultId,
        nodeId,
        sectionName: change.name,
      });
    // Never chain onto a write older than one this device saw, or another of the same version.
    const mark = await local.mark({ vaultId: change.vaultId, nodeId, sectionName: change.name });
    if (mark !== undefined) {
      if (latest === undefined || latest.dataVersion < mark.dataVersion) {
        throw new CloakSectionError(change.vaultId, nodeId, change.name, 'rollback');
      }
      if (
        latest.dataVersion === mark.dataVersion &&
        !equalBytes(headerWriteHash(fromWireHeader(latest)), mark.writeHash)
      ) {
        throw new CloakSectionError(change.vaultId, nodeId, change.name, 'fork');
      }
    }
    const address = {
      vaultId: change.vaultId,
      nodeId,
      sectionName: change.name,
      vaultKeyVersion: head.keyVersion,
    };
    const fields: SectionWriteFields = {
      ...address,
      nodeType: change.type,
      homeVaultId: origin.homeVaultId,
      ownerUserId: origin.ownerUserId,
      nodeKey: origin.nodeKey,
      dataVersion: (latest?.dataVersion ?? 0) + 1,
      deleted,
      logSeq: head.seq,
      logHeadHash: head.hash,
      previousWriteHash: latest === undefined ? undefined : headerWriteHash(fromWireHeader(latest)),
      writerUserId: self.userId,
      writerKeyVersion: self.keyVersion,
      ciphertext: deleted
        ? undefined
        : encryptSection(
            await book.key(change.vaultId, head.keyVersion),
            address,
            encodeContent(change.content),
          ),
    };
    return {
      wire: toWireWrite(fields, signSectionWrite(fields, self.secrets.signingSeed)),
      fields,
    };
  }

  /**
   * Stores what this device wrote, so later reads and key replacements recognise it. Only the
   * write this device signed is remembered: the server's reply must be exactly that write.
   */
  async function remember(
    served: Schemas['SectionHeader'],
    fields: SectionWriteFields,
  ): Promise<SectionInfo> {
    const hash = writeHash(fields);
    const written = validHeader(served);
    if (
      written.vaultId !== fields.vaultId ||
      written.nodeId !== fields.nodeId ||
      written.sectionName !== fields.sectionName ||
      !equalBytes(headerWriteHash(fromWireHeader(written)), hash)
    ) {
      throw new CloakVaultLogError(fields.vaultId, 'state_mismatch');
    }
    const key: SectionKey = {
      vaultId: fields.vaultId,
      nodeId: fields.nodeId,
      sectionName: fields.sectionName,
    };
    await local.setOwnWrite(key, hash);
    await local.raiseMark(key, { dataVersion: fields.dataVersion, writeHash: hash });
    return {
      vaultId: fields.vaultId,
      nodeId: fields.nodeId,
      name: fields.sectionName,
      type: fields.nodeType,
      dataVersion: fields.dataVersion,
      changeSeq: written.changeSeq,
      writerUserId: self.hostUserId,
      node: {
        owner: keyring.hostIdOf(fields.ownerUserId) ?? fields.ownerUserId,
        home: fields.homeVaultId,
        key: fields.nodeKey,
      },
    };
  }

  /** Writes changes, as one request or a batch. */
  async function writeAll(changes: readonly SectionChange[]): Promise<readonly SectionInfo[]> {
    return retrying([...new Set(changes.map((change) => change.vaultId))], async () => {
      const fresh = new Map<string, VaultRecord>();
      const prepared = [];
      for (const change of changes) prepared.push(await prepare(change, fresh));
      const [single] = prepared;
      if (prepared.length === 1 && single !== undefined) {
        const { fields } = single;
        const written = await body(
          api.PUT('/vaults/{vaultId}/sections/{nodeId}/{sectionName}', {
            params: {
              path: {
                vaultId: fields.vaultId,
                nodeId: fields.nodeId,
                sectionName: fields.sectionName,
              },
            },
            body: single.wire,
          }),
        );
        return [await remember(written, fields)];
      }
      const response = await body(
        api.POST('/sections/batch-write', {
          body: {
            items: prepared.map(({ wire, fields }) => ({
              ...wire,
              vaultId: fields.vaultId,
              nodeId: fields.nodeId,
              sectionName: fields.sectionName,
            })),
          },
        }),
      );
      if (response.items.length !== prepared.length)
        throw new CloakVaultLogError(changes[0]?.vaultId ?? '', 'state_mismatch');
      const infos = [];
      for (const [index, written] of response.items.entries()) {
        const fields = prepared[index]?.fields;
        if (fields === undefined) throw new CloakVaultLogError(written.vaultId, 'state_mismatch');
        infos.push(await remember(written, fields));
      }
      return infos;
    });
  }

  /**
   * The operations themselves. They call each other through this object, inside the one gate
   * run their caller started, so closing waits for the outermost and never for itself.
   */
  const session: Omit<CloakSession, 'closed' | 'close'> = {
    userId: self.hostUserId,
    keyVersion: self.keyVersion,
    fingerprint: fingerprint(self.keys),

    async fingerprintOf(hostUserId) {
      const userId = cloakUserId(hostUserId);
      // Pinning happens only through log verification or a confirmed fingerprint, never here.
      const pinned = (await local.pin(userId)) !== undefined;
      if (pinned) await keyring.load([userId], true);
      const newest = pinned ? keyring.newest(userId) : await keyring.peek(userId);
      if (newest === undefined) throw noIdentity();
      return fingerprint(newest);
    },

    confirmFingerprint(hostUserId, confirmed) {
      return keyring.confirm(cloakUserId(hostUserId), confirmed);
    },

    async listVaults(options = {}) {
      const page = await body(
        api.GET('/vaults', {
          params: {
            query: {
              ...(options.limit === undefined ? {} : { limit: options.limit }),
              ...(options.cursor === undefined ? {} : { cursor: options.cursor }),
              ...(options.pending === true ? { pending: true } : {}),
            },
          },
        }),
      );
      // Names of who added the user, without trusting anyone's keys for it.
      await keyring.learnNames(
        page.items.flatMap((vault) =>
          vault.addedByUserId === undefined ? [] : [vault.addedByUserId],
        ),
      );
      return {
        items: page.items.map((vault) => ({
          id: vault.id,
          role: vault.role,
          createdAt: vault.createdAt,
          accepted: vault.accepted,
          ...(vault.addedByUserId === undefined
            ? {}
            : { addedBy: keyring.hostIdOf(vault.addedByUserId) ?? vault.addedByUserId }),
        })),
        ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
      };
    },

    async createVault() {
      const created: OwnEntries = [];
      const vaultId = crypto.randomUUID();
      const vaultKey = generateVaultKey();
      const fields: LogEntryFields = {
        vaultId,
        seq: 1,
        kind: 'vault_created',
        subjectUserId: self.userId,
        role: 'owner',
        keyVersion: 1,
        subjectKeys: keysDigest(self.keys),
        subjectKeyVersion: self.keyVersion,
        keyCommitment: keyCommitment(vaultKey, vaultId, 1),
        requestEnd: true,
        authorUserId: self.userId,
        authorKeyVersion: self.keyVersion,
      };
      const envelope = await sealEnvelope(
        self.keys.encryptionPublicKey,
        vaultId,
        1,
        { userId: self.userId, userKeyVersion: self.keyVersion },
        vaultKey,
      );
      await body(
        api.POST('/vaults', {
          body: {
            id: vaultId,
            keyEnvelope: toBase64Url(envelope),
            log: signEntry(fields, created),
          },
        }),
      );
      await keepOwn(created);
      return reopen(vaultId);
    },

    openVault: reopen,

    async deleteVault(vaultId) {
      await retrying([vaultId], async (own) => {
        const record = await book.verify(vaultId);
        const log = nextEntry(record, own, {
          kind: 'vault_deleted',
          keyVersion: logHead(record.state).keyVersion,
          requestEnd: true,
        });
        await noBody(
          api.POST('/vaults/{vaultId}/deletion', { params: { path: { vaultId } }, body: { log } }),
        );
      });
      await forget(vaultId, true);
    },

    async acceptVault(vaultId) {
      await noBody(api.PUT('/vaults/{vaultId}/acceptance', { params: { path: { vaultId } } }));
    },

    async acceptInvitationsFrom(hostUserId) {
      await noBody(
        api.POST('/invitations/acceptance', {
          body: { inviterUserId: cloakUserId(hostUserId) },
        }),
      );
    },

    async createNode(homeVaultId, nodeKey) {
      const node: NodeRef = { owner: self.hostUserId, home: homeVaultId, key: nodeKey };
      const nodeId = nodeIdOf(originOf(node));
      await nodeEntry(homeVaultId, (record) => {
        // A vault the user never accepted may be one a server or host steered them into; never
        // make it the home of a secret. The flag is the server's word, so it can only refuse.
        if (!record.view.accepted)
          throw new CloakSectionError(homeVaultId, nodeId, '', 'not_shared');
        if (record.state.nodes.has(nodeId)) return undefined;
        return { kind: 'node_created', nodeId, nodeKey };
      });
      return node;
    },

    async shareNode(node, vaultId, sections) {
      const origin = originOf(node);
      if (origin.ownerUserId !== self.userId || origin.homeVaultId === vaultId)
        throw new RangeError('Only its owner shares a node, and never into its home');
      await nodeEntry(vaultId, () => ({
        kind: 'node_shared',
        nodeId: nodeIdOf(origin),
        homeVaultId: origin.homeVaultId,
        nodeKey: origin.nodeKey,
        sections: formatSectionScope(sections),
      }));
    },

    async unshareNode(node, vaultId, sections) {
      await nodeEntry(vaultId, () => ({
        kind: 'node_unshared',
        nodeId: nodeIdOf(originOf(node)),
        sections: formatSectionScope(sections),
      }));
    },

    forgetVault(vaultId) {
      return forget(vaultId, false);
    },

    async deleteAccount() {
      // Accepted vaults are left or deleted first. Vaults the user never accepted do not hold the
      // deletion up: the server drops their envelopes, and their admins remove the member (§5.7).
      const vaultIds: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await session.listVaults(cursor === undefined ? {} : { cursor });
        vaultIds.push(...page.items.map((vault) => vault.id));
        cursor = page.nextCursor;
      } while (cursor !== undefined);

      // Decide every vault first, so nothing changes when one blocks the deletion.
      const deletions: string[] = [];
      const departures: string[] = [];
      const blocking: string[] = [];
      for (const vaultId of vaultIds) {
        const record = await book.verify(vaultId);
        const me = committed(vaultId, record, self.userId);
        const others = [...record.state.members].filter(([userId]) => userId !== self.userId);
        await keyring.load(
          others.map(([userId]) => userId),
          true,
        );
        // A deleted member can never act again, so they do not count as someone left behind.
        const living = others.filter(([userId]) => !keyring.isDeleted(userId));
        if (me.role === 'owner' && living.length === 0) deletions.push(vaultId);
        else if (me.role === 'owner' && !living.some(([, member]) => member.role === 'owner'))
          blocking.push(vaultId);
        else departures.push(vaultId);
      }
      if (blocking.length > 0) throw new CloakAccountNotEmptyError(blocking);

      for (const vaultId of deletions) await session.deleteVault(vaultId);
      for (const vaultId of departures) await session.leave(vaultId);
      // Signed, and only for a few minutes, so neither the host's session alone nor a captured
      // request can delete the account (§5.7).
      const identity = await body(api.GET('/identity'));
      const notAfter = Math.floor(Date.now() / 1000) + DELETION_WINDOW_SECONDS;
      const statement = identityDeletionMessage(
        self.userId,
        self.keyVersion,
        identity.credentialsVersion,
        notAfter,
      );
      await noBody(
        api.POST('/identity/deletion', {
          body: {
            credentialsVersion: identity.credentialsVersion,
            notAfter,
            signature: toBase64Url(signIdentityStatement(statement, self.secrets.signingSeed)),
          },
        }),
      );
      await local.clear();
    },

    async addMember(vaultId, hostUserId, role) {
      const userId = cloakUserId(hostUserId);
      if ((await local.pin(userId)) === undefined) {
        const served = await keyring.peek(userId);
        if (served === undefined) throw noIdentity();
        throw new CloakFingerprintRequiredError(hostUserId, fingerprint(served));
      }
      await keyring.load([userId], true);
      if (keyring.isDeleted(userId)) throw deletedIdentity();
      const keys = keyring.newest(userId);
      if (keys === undefined) throw noIdentity();
      return retrying([vaultId], async (own) => {
        const record = await book.verify(vaultId);
        const head = logHead(record.state);
        const envelope = await sealEnvelope(
          keys.encryptionPublicKey,
          vaultId,
          head.keyVersion,
          { userId, userKeyVersion: keys.keyVersion },
          await book.key(vaultId, head.keyVersion),
        );
        const log = nextEntry(record, own, {
          kind: 'member_added',
          subjectUserId: userId,
          role,
          keyVersion: head.keyVersion,
          subjectKeys: keysDigest(keys),
          subjectKeyVersion: keys.keyVersion,
          requestEnd: true,
        });
        await body(
          api.POST('/vaults/{vaultId}/members', {
            params: { path: { vaultId } },
            body: {
              userId,
              role,
              keyVersion: head.keyVersion,
              userKeyVersion: keys.keyVersion,
              keyEnvelope: toBase64Url(envelope),
              log,
            },
          }),
        );
        return reopen(vaultId);
      });
    },

    setRole(vaultId, hostUserId, role) {
      const userId = cloakUserId(hostUserId);
      return retrying([vaultId], async (own) => {
        const record = await book.verify(vaultId);
        const member = committed(vaultId, record, userId);
        const losesWrite = roleIncludes(member.role, 'editor') && !roleIncludes(role, 'editor');
        const checkpoint = losesWrite ? await buildCheckpoint(vaultId) : undefined;
        const log = nextEntry(record, own, {
          kind: 'member_role_set',
          subjectUserId: userId,
          role,
          keyVersion: logHead(record.state).keyVersion,
          subjectKeys: member.keysDigest,
          subjectKeyVersion: member.keyVersion,
          checkpoint: checkpoint?.root,
          requestEnd: true,
        });
        await body(
          api.PATCH('/vaults/{vaultId}/members/{userId}', {
            params: { path: { vaultId, userId } },
            body: {
              role,
              log,
              ...(checkpoint === undefined || checkpoint.leftOut.length === 0
                ? {}
                : { leftOut: checkpoint.leftOut }),
            },
          }),
        );
        return reopen(vaultId);
      });
    },

    rotate(vaultId, removeHostIds = [], options = {}) {
      const named = removeHostIds.map(cloakUserId);
      return retrying([vaultId], async (own) => {
        const record = await book.verify(vaultId);
        // Whether people are deleted is learned afresh, so the envelopes skip them.
        await keyring.load(record.state.members.keys(), true);
        const checkpoint = await buildCheckpoint(vaultId);
        const request = await rotationOf(vaultId, record, named, options, checkpoint, own);
        await body(
          api.POST('/vaults/{vaultId}/rotations', { params: { path: { vaultId } }, body: request }),
        );
        return reopen(vaultId);
      });
    },

    async openVaults(vaultIds) {
      const records = await book.verifyMany(vaultIds);
      return new Map(
        [...records].map(([vaultId, record]) => [
          vaultId,
          record === undefined ? undefined : toVerified(vaultId, record),
        ]),
      );
    },

    async addMemberToVaults(vaultIds, hostUserId, role) {
      const added: string[] = [];
      const failed: VaultFailure[] = [];
      // Adding stops halfway only with less access than asked, so vault by vault is safe.
      for (const vaultId of new Set(vaultIds)) {
        try {
          await session.addMember(vaultId, hostUserId, role);
          added.push(vaultId);
        } catch (error: unknown) {
          failed.push({ vaultId, error });
        }
      }
      return { added, failed };
    },

    removeFromVaults(vaultIds, removeHostIds, options = {}) {
      const named = removeHostIds.map(cloakUserId);
      const unique = [...new Set(vaultIds)];
      if (unique.length > 100) throw new RangeError('At most 100 vaults rotate together');
      return retrying(unique, async (own) => {
        const records = await book.verifyMany(unique);
        const touched: { readonly vaultId: string; readonly record: VaultRecord }[] = [];
        for (const vaultId of unique) {
          const record = records.get(vaultId);
          if (record === undefined) throw notVisible(vaultId);
          await keyring.load(record.state.members.keys(), true);
          const affected = [...record.state.members.keys()].some(
            (userId) =>
              named.includes(userId) ||
              (options.removeDeleted === true &&
                userId !== self.userId &&
                keyring.isDeleted(userId)),
          );
          if (affected) touched.push({ vaultId, record });
        }
        if (touched.length === 0) return [];
        // One request, one transaction: everyone is removed from all of them or from none.
        const checkpoints = await buildCheckpoints(touched.map(({ vaultId }) => vaultId));
        const items = [];
        for (const { vaultId, record } of touched) {
          const checkpoint = checkpoints.get(vaultId);
          if (checkpoint === undefined) throw new RangeError('No checkpoint was built');
          items.push({
            vaultId,
            ...(await rotationOf(vaultId, record, named, options, checkpoint, own)),
          });
        }
        await body(api.POST('/rotations/batch-apply', { body: { items } }));
        const fresh = await book.verifyMany(touched.map(({ vaultId }) => vaultId));
        return touched.map(({ vaultId }) => {
          const record = fresh.get(vaultId);
          if (record === undefined) throw notVisible(vaultId);
          return toVerified(vaultId, record);
        });
      });
    },

    async leave(vaultId) {
      await retrying([vaultId], async (own) => {
        const record = await book.verify(vaultId);
        const me = committed(vaultId, record, self.userId);
        const checkpoint = roleIncludes(me.role, 'editor')
          ? await buildCheckpoint(vaultId)
          : undefined;
        const log = nextEntry(record, own, {
          kind: 'member_removed',
          subjectUserId: self.userId,
          keyVersion: logHead(record.state).keyVersion,
          subjectKeys: me.keysDigest,
          subjectKeyVersion: me.keyVersion,
          checkpoint: checkpoint?.root,
          requestEnd: true,
        });
        await noBody(
          api.POST('/vaults/{vaultId}/departures', {
            params: { path: { vaultId } },
            body: {
              log,
              ...(checkpoint === undefined || checkpoint.leftOut.length === 0
                ? {}
                : { leftOut: checkpoint.leftOut }),
            },
          }),
        );
      });
      // Only once the departure and its own entries are kept, so nothing about the vault but its
      // verified head stays behind.
      await forget(vaultId, true);
    },

    async deliverEnvelopes(vaultId) {
      const record = await book.verify(vaultId);
      const head = logHead(record.state);
      const vaultKey = await book.key(vaultId, head.keyVersion);
      let delivered = 0;
      for (const userId of record.state.sinceRotation.replacedKeys) {
        const member = record.state.members.get(userId);
        const keys = member === undefined ? undefined : keyring.keysOf(userId, member.keyVersion);
        if (member === undefined || keys === undefined || keyring.isDeleted(userId)) continue;
        const envelope = await sealEnvelope(
          keys.encryptionPublicKey,
          vaultId,
          head.keyVersion,
          { userId, userKeyVersion: member.keyVersion },
          vaultKey,
        );
        await noBody(
          api.PUT('/vaults/{vaultId}/members/{userId}/envelope', {
            params: { path: { vaultId, userId } },
            body: {
              keyVersion: head.keyVersion,
              userKeyVersion: member.keyVersion,
              keyEnvelope: toBase64Url(envelope),
            },
          }),
        );
        delivered += 1;
      }
      return delivered;
    },

    recordKeyReplacement(vaultId) {
      return retrying([vaultId], async (own) => {
        const record = await book.verify(vaultId);
        const head = logHead(record.state);
        const me = committed(vaultId, record, self.userId);
        if (me.keyVersion === self.keyVersion) {
          return {
            vault: toVerified(vaultId, record),
            unrecognizedEntries: await unrecognized(vaultId, record),
          };
        }
        const checkpoint = roleIncludes(me.role, 'editor')
          ? await buildCheckpoint(vaultId, self.keyVersion)
          : undefined;
        let envelope: string | undefined;
        try {
          const vaultKey = await book.key(vaultId, head.keyVersion);
          envelope = toBase64Url(
            await sealEnvelope(
              self.keys.encryptionPublicKey,
              vaultId,
              head.keyVersion,
              { userId: self.userId, userKeyVersion: self.keyVersion },
              vaultKey,
            ),
          );
        } catch (error: unknown) {
          if (!(error instanceof CloakKeyUnavailableError)) throw error;
        }
        const log = nextEntry(record, own, {
          kind: 'member_keys_replaced',
          subjectUserId: self.userId,
          keyVersion: head.keyVersion,
          subjectKeys: keysDigest(self.keys),
          subjectKeyVersion: self.keyVersion,
          checkpoint: checkpoint?.root,
          requestEnd: true,
        });
        await body(
          api.POST('/vaults/{vaultId}/key-replacements', {
            params: { path: { vaultId } },
            body: {
              log,
              ...(envelope === undefined ? {} : { keyEnvelope: envelope }),
              ...(checkpoint === undefined || checkpoint.leftOut.length === 0
                ? {}
                : { leftOut: checkpoint.leftOut }),
            },
          }),
        );
        const after = await book.verify(vaultId);
        return {
          vault: toVerified(vaultId, after),
          unrecognizedEntries: await unrecognized(vaultId, after),
        };
      });
    },

    async readSection(vaultId, nodeId, name) {
      const wire = await body(
        api.GET('/vaults/{vaultId}/sections/{nodeId}/{sectionName}', {
          params: { path: { vaultId, nodeId, sectionName: name } },
        }),
      );
      requirePlace(vaultId, [wire], { vaultId, nodeId, sectionName: name });
      // Where a node lives can change at any entry (§7.7), so the log is read to its head first.
      await book.verify(vaultId);
      const [section] = await readWrites(vaultId, [wire]);
      if (section === undefined) throw new RangeError('A read returned nothing');
      return section;
    },

    async readNode(nodeId) {
      const node = await body(api.GET('/nodes/{nodeId}', { params: { path: { nodeId } } }));
      requirePlace(nodeId, node.sections, { nodeId });
      const byVault = new Map<string, Schemas['SectionWrite'][]>();
      for (const wire of node.sections) {
        byVault.set(wire.vaultId, [...(byVault.get(wire.vaultId) ?? []), wire]);
      }
      const read = new Map<Schemas['SectionWrite'], DecryptedSection>();
      // Every vault's log to its head, at once, since where a node lives can change (§7.7).
      await book.verifyMany([...byVault.keys()]);
      for (const [vaultId, wires] of byVault) {
        const checked = await readWrites(vaultId, wires);
        wires.forEach((wire, position) => {
          const section = checked[position];
          if (section !== undefined) read.set(wire, section);
        });
      }
      const sections = node.sections.flatMap((wire) => {
        const section = read.get(wire);
        return section === undefined ? [] : [section];
      });
      // §8.1: one node with two types, or one section live in two vaults, is a conflict to show.
      const live = sections.filter((section) => section.status === 'ok');
      const types = new Set(live.map((section) => section.type));
      const names = live.map((section) => section.name);
      return {
        nodeId,
        sections,
        typeConflict: types.size > 1,
        duplicateNames: [...new Set(names.filter((name, index) => names.indexOf(name) !== index))],
      };
    },

    async readVault(vaultId) {
      return readVault(vaultId, true);
    },

    async changes(vaultId, afterChange = 0) {
      // Where a node lives can change at any entry (§7.7), so the log is read to its head first.
      await book.verify(vaultId);
      const sections = [];
      const removed: SectionRemoval[] = [];
      let after = afterChange;
      let lastChangeSeq: number;
      for (;;) {
        const page = await feed(vaultId, after);
        lastChangeSeq = page.lastChangeSeq;
        requirePlace(vaultId, page.items, { vaultId });
        sections.push(...(await readWrites(vaultId, page.items)));
        removed.push(
          ...page.removed.map((removal) => ({
            nodeId: removal.nodeId,
            name: removal.sectionName,
            changeSeq: removal.changeSeq,
          })),
        );
        if (page.throughChangeSeq >= page.lastChangeSeq) break;
        after = page.throughChangeSeq;
      }
      return { sections, removed, lastChangeSeq };
    },

    async writeSection(vaultId, node, name, change) {
      const [written] = await writeAll([
        { vaultId, node, name, type: change.type, content: change.content },
      ]);
      if (written === undefined) throw new RangeError('A write returned nothing');
      return written;
    },

    async deleteSection(vaultId, node, name, type) {
      const [written] = await writeAll([{ vaultId, node, name, type }]);
      if (written === undefined) throw new RangeError('A write returned nothing');
      return written;
    },

    writeSections(changes) {
      return writeAll(changes);
    },

    async moveSection(node, name, fromVaultId, toVaultId) {
      const nodeId = nodeIdOf(originOf(node));
      const current = await session.readSection(fromVaultId, nodeId, name);
      if (current.status !== 'ok')
        throw new CloakSectionError(
          fromVaultId,
          nodeId,
          name,
          current.status === 'refused' ? current.reason : 'bad_deletion',
        );
      const written = await writeAll([
        { vaultId: fromVaultId, node, name, type: current.type },
        { vaultId: toVaultId, node, name, type: current.type, content: current.content },
      ]);
      const moved = written[1];
      if (moved === undefined) throw new RangeError('A write returned nothing');
      return moved;
    },
  };

  const gate = createSessionGate();

  /** Closes the session once every running operation ended; see {@link CloakSession.close}. */
  async function close(): Promise<void> {
    const first = !gate.closed;
    await gate.shut();
    if (!first) return;
    book.close();
    local.close();
    wipeIdentitySecrets(self.secrets);
  }

  /** Every operation of {@link session}, run through the gate. */
  const operations = Object.fromEntries(
    Object.entries(session).map(([name, value]) => [
      name,
      typeof value === 'function'
        ? (...args: unknown[]) =>
            gate.run(() => (value as (...parameters: unknown[]) => Promise<unknown>)(...args))
        : value,
    ]),
  );
  return {
    // Each function of `session` is replaced by one taking the same arguments and returning the
    // same promise, so the shape is the one `session` was checked against.
    ...(operations as Omit<CloakSession, 'closed' | 'close'>),
    get closed() {
      return gate.closed;
    },
    close,
    async deleteAccount() {
      // The account is gone, and with it the reason to hold its keys.
      await gate.run(() => session.deleteAccount());
      await close();
    },
  };
}

/**
 * Whether a node lives in a vault for a section's name, by its verified log (`PROTOCOL.md` §7.7):
 * created there, its home, or shared there by name or whole, with the same owner, home and key.
 */
function livesIn(
  state: VaultLogState,
  vaultId: string,
  nodeId: string,
  origin: NodeOrigin,
  sectionName: string,
): boolean {
  if (origin.homeVaultId === vaultId) {
    const node = state.nodes.get(nodeId);
    return node?.ownerUserId === origin.ownerUserId && node.nodeKey === origin.nodeKey;
  }
  const share = state.shares.get(nodeId);
  return (
    share?.ownerUserId === origin.ownerUserId &&
    share.homeVaultId === origin.homeVaultId &&
    share.nodeKey === origin.nodeKey &&
    sharedSince(state, nodeId, sectionName) !== undefined
  );
}

/**
 * The cache bucket of a section: FNV-1a of its address, so the spread is fixed and even. Nothing
 * depends on it being hard to predict.
 *
 * @param key `nodeId/sectionName`.
 * @returns A bucket below {@link SECTION_CACHE_BUCKETS}.
 */
function bucketOf(key: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < key.length; index += 1) {
    hash ^= key.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash % SECTION_CACHE_BUCKETS;
}

/** The refusal for a person the server marks deleted, as the server itself would answer. */
function deletedIdentity(): CloakApiError {
  return new CloakApiError(410, {
    code: 'identity_deleted',
    detail: 'The user is deleted.',
  });
}

/** The error for a person without an identity, as the server reports it elsewhere. */
function noIdentity(): CloakApiError {
  return new CloakApiError(404, {
    code: 'identity_required',
    detail: 'The user has no identity yet.',
  });
}
