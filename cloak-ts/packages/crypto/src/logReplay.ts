import { sha256 } from '@noble/hashes/sha2.js';

import { equalBytes, isAbsent } from './bytes.ts';
import { checkpointRoot, type CheckpointLeaf } from './checkpoints.ts';
import { derivesNode, isValidNodeKey, parseSectionScope } from './nodes.ts';
import { keysDigest, type PublicKeys } from './publicKeys.ts';
import { checkSignature, type SignatureRefusal } from './signatures.ts';
import {
  ROLE_CODE,
  logMessage,
  roleIncludes,
  type LogEntryFields,
  type LogEntryKind,
  type Role,
} from './vaultLog.ts';

/** A log entry as a member reads it. */
export interface LogEntry extends LogEntryFields {
  /** The author's signature over {@link logMessage}. */
  readonly signature: Uint8Array;
  /** `entryHash` as the server states it; when present it must match. */
  readonly entryHash?: Uint8Array | undefined;
  /** Leaves of the entry's checkpoint, when the reader has them; their root must match. */
  readonly checkpointLeaves?: readonly CheckpointLeaf[] | undefined;
}

/** A user's membership: their role and the key version it commits (`PROTOCOL.md` §7.2). */
export interface Membership {
  /** Role in the vault. */
  readonly role: Role;
  /** Committed identity key version; only it carries the member's rights. */
  readonly keyVersion: number;
  /** `keysDigest` of that version. */
  readonly keysDigest: Uint8Array;
}

/**
 * One verified entry as a snapshot keeps it: enough to place writes on the log and to tell who
 * signed what, without the entry itself.
 */
export interface LogPoint {
  /** Sequence number of the entry. */
  readonly seq: number;
  /** Its `entryHash`. */
  readonly hash: Uint8Array;
  /** Whether it ends a request, so a write may cite it. */
  readonly head: boolean;
  /** The vault key version after it. */
  readonly keyVersion: number;
  /** Who signed it. */
  readonly authorUserId: string;
  /** The identity key version that signed it. */
  readonly authorKeyVersion: number;
}

/** A change of one user's membership, as of an entry. */
export interface MembershipChange {
  /** The entry that made it. */
  readonly seq: number;
  /** The membership from that entry on; absent once the user is no longer a member. */
  readonly membership?: Membership | undefined;
}

/** A node created in a vault, its home (`PROTOCOL.md` §7.7). */
export interface CreatedNode {
  /** The node's owner, who created it. */
  readonly ownerUserId: string;
  /** The node's key. */
  readonly nodeKey: string;
  /** The `seq` of `node_created`; the node's sections are valid in its home from there. */
  readonly seq: number;
}

/** A node shared into a vault from its home (`PROTOCOL.md` §7.7). */
export interface NodeShare {
  /** The node's owner, who shared it. */
  readonly ownerUserId: string;
  /** The node's home vault. */
  readonly homeVaultId: string;
  /** The node's key. */
  readonly nodeKey: string;
  /** The `seq` from which every name is shared, when the node is shared with `*`. */
  readonly all?: number | undefined;
  /** The `seq` from which each name shared by name is shared. */
  readonly names: ReadonlyMap<string, number>;
}

/**
 * The `seq` from which a section's name is shared into a vault now, if it is.
 *
 * @param state A verified log.
 * @param nodeId The node.
 * @param sectionName The section's name.
 * @returns The `seq`, or `undefined` when the name is not shared there.
 */
export function sharedSince(
  state: VaultLogState,
  nodeId: string,
  sectionName: string,
): number | undefined {
  const share = state.shares.get(nodeId);
  return share === undefined ? undefined : (share.names.get(sectionName) ?? share.all);
}

/** Who exposed the current vault key since the last rotation (`PROTOCOL.md` §7.4). */
export interface RotationExposure {
  /** Members who left by themselves, and so still know the current key. */
  readonly departed: readonly string[];
  /** Members who recorded a key replacement, whose old keys still open the current key. */
  readonly replacedKeys: readonly string[];
}

/** An entry that carries a checkpoint. */
export interface CheckpointRecord {
  /** Sequence number of the entry. */
  readonly seq: number;
  /** The signed root. */
  readonly root: Uint8Array;
}

/**
 * A verified vault log (`PROTOCOL.md` §15): one point per entry, each member's history, the
 * checkpoints and the key commitments. It grows with the log, not with the log times the members.
 * A client keeps it as the vault's snapshot and continues it with new entries.
 */
export interface VaultLogState {
  /** The vault. */
  readonly vaultId: string;
  /** One point per entry; index `seq - 1`. Never empty, and the last one is a head. */
  readonly points: readonly LogPoint[];
  /** Members after the last entry, by user id. */
  readonly members: ReadonlyMap<string, Membership>;
  /** Every change of each user's membership, oldest first; see {@link membershipAt}. */
  readonly history: ReadonlyMap<string, readonly MembershipChange[]>;
  /** Entries carrying a checkpoint, in log order. */
  readonly checkpoints: readonly CheckpointRecord[];
  /** Key commitment of every vault key version. */
  readonly commitments: ReadonlyMap<number, Uint8Array>;
  /** Newest key version each user's `member_keys_replaced` entries record (§7.6 rule 4). */
  readonly recordedKeyVersions: ReadonlyMap<string, number>;
  /** Who exposed the current key since the last rotation. */
  readonly sinceRotation: RotationExposure;
  /** Nodes created in the vault, their home, by node id (§7.7). */
  readonly nodes: ReadonlyMap<string, CreatedNode>;
  /** Nodes shared into the vault from their homes, by node id (§7.7). */
  readonly shares: ReadonlyMap<string, NodeShare>;
  /** Whether an owner deleted the vault; nothing follows that entry (§12.3). */
  readonly deleted: boolean;
  /**
   * The last `seq` at which where nodes live changed: a node entry, or the removal of a member
   * whose shares ended with them; 0 when never. A reader that judged writes before it judges them
   * again (§15).
   */
  readonly placesChangedAt: number;
}

/**
 * Why a log is refused (`PROTOCOL.md` §7.6):
 *
 * - `broken_chain`: `seq`, `previousHash`, `entryHash` or the vault id do not continue the log;
 * - `bad_flag`: `requestEnd` is not 0 or 1, as decoded by the caller;
 * - `unverified_keys`: the author's or subject's keys are not the committed or trusted ones;
 * - `superseded_keys`: the author signs with a key version the reader knows was replaced;
 * - a {@link SignatureRefusal}: the signature does not verify;
 * - `bad_request_shape`, `unfinished_request`: the request is not one of §7.3's shapes;
 * - `unexpected_field`: the kind sets a field it must not;
 * - `invalid_entry`: the subject's state does not allow the entry;
 * - `not_authorized`: the author's role is too weak;
 * - `missing_checkpoint`: an entry that takes away the right to write carries no checkpoint;
 * - `no_owner`: the vault would be left without an owner;
 * - `bad_checkpoint`: the leaves the reader holds do not give the signed root;
 * - `vault_deleted`: an entry follows the vault's deletion.
 */
export type LogRefusal =
  | 'broken_chain'
  | 'bad_flag'
  | 'unverified_keys'
  | 'superseded_keys'
  | SignatureRefusal
  | 'bad_request_shape'
  | 'unfinished_request'
  | 'unexpected_field'
  | 'invalid_entry'
  | 'not_authorized'
  | 'missing_checkpoint'
  | 'no_owner'
  | 'bad_checkpoint'
  | 'vault_deleted';

/** Outcome of replaying a log. */
export type ReplayResult =
  | {
      /** Discriminant. */
      readonly ok: true;
      /** The verified state. */
      readonly state: VaultLogState;
    }
  | {
      /** Discriminant. */
      readonly ok: false;
      /** Why the log is refused. */
      readonly reason: LogRefusal;
      /** First entry that breaks a rule. */
      readonly failSeq: number;
    };

/** What a replay needs to know about people's keys. */
export interface ReplayOptions {
  /**
   * The public keys of a user's key version, when the reader trusts that version: pinned or
   * reached through verified key statements (`PROTOCOL.md` §5.2, §9).
   */
  readonly keysOf: (userId: string, keyVersion: number) => PublicKeys | undefined;
  /**
   * Whether the reader knows a later version of the user's keys. Pass it only for entries the
   * reader had not verified before it learned of that version (`PROTOCOL.md` §7.6 rule 4).
   */
  readonly isSuperseded?: ((userId: string, keyVersion: number) => boolean) | undefined;
}

/** Kinds that may make up a request alone. */
const SINGLE_KINDS: ReadonlySet<LogEntryKind> = new Set([
  'vault_created',
  'member_added',
  'member_role_set',
  'member_keys_replaced',
  'node_created',
  'node_shared',
  'node_unshared',
  'vault_deleted',
]);

/** Optional fields a kind may set, apart from the checkpoint. */
type Field =
  'subject' | 'role' | 'subjectKeys' | 'keyCommitment' | 'node' | 'home' | 'nodeKey' | 'sections';

/** The fields each kind sets (`PROTOCOL.md` §7.2). */
const KIND_FIELDS = {
  vault_created: ['subject', 'role', 'subjectKeys', 'keyCommitment'],
  member_added: ['subject', 'role', 'subjectKeys'],
  member_role_set: ['subject', 'role', 'subjectKeys'],
  member_removed: ['subject', 'subjectKeys'],
  member_keys_replaced: ['subject', 'subjectKeys'],
  key_rotated: ['keyCommitment'],
  node_created: ['node', 'nodeKey'],
  node_shared: ['node', 'home', 'nodeKey', 'sections'],
  node_unshared: ['node', 'sections'],
  vault_deleted: [],
} as const satisfies Record<LogEntryKind, readonly Field[]>;

/** Most names one share may hold (`PROTOCOL.md` §7.7). */
const MAX_SHARED_NAMES = 1000;

/** The nil UUID, an absent subject. */
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

/**
 * Replays and verifies a vault log (`PROTOCOL.md` §7.6), from `seq` 1 or from a verified snapshot.
 *
 * @param vaultId The vault the reader asked for; every entry must belong to it.
 * @param entries Entries in order: from `seq` 1, or from the entry after [from]'s last.
 * @param options Trusted keys.
 * @param from A verified snapshot to continue; absent to start from `seq` 1.
 * @returns The verified state, or the first rule broken.
 */
export function replayVaultLog(
  vaultId: string,
  entries: readonly LogEntry[],
  options: ReplayOptions,
  from?: VaultLogState,
): ReplayResult {
  if (from !== undefined && from.vaultId !== vaultId) {
    return { ok: false, reason: 'broken_chain', failSeq: from.points.length + 1 };
  }
  // Copied once per replay, then changed in place: a failed replay leaves [from] untouched.
  const points: LogPoint[] = [...(from?.points ?? [])];
  const checkpoints: CheckpointRecord[] = [...(from?.checkpoints ?? [])];
  const commitments = new Map(from?.commitments ?? []);
  const members = new Map(from?.members ?? []);
  const history = new Map(from?.history ?? []);
  const copiedHistories = new Set<string>();
  const recordedKeyVersions = new Map(from?.recordedKeyVersions ?? []);
  const departed = new Set(from?.sinceRotation.departed ?? []);
  const replacedKeys = new Set(from?.sinceRotation.replacedKeys ?? []);
  const shares = new Map(from?.shares ?? []);
  const nodes = new Map(from?.nodes ?? []);
  let deleted = from?.deleted ?? false;
  let placesChangedAt = from?.placesChangedAt ?? 0;
  let owners = [...members.values()].filter((member) => member.role === 'owner').length;
  const last = points.at(-1);
  let keyVersion = last?.keyVersion ?? 0;
  let previousHash = last?.hash;
  let request:
    | {
        readonly author: string;
        /** The author's role before the request: it decides every entry of it (§7.3). */
        readonly rights: Role | undefined;
        readonly kinds: { kind: LogEntryKind; self: boolean }[];
      }
    | undefined;

  /** Changes a user's membership as of entry [seq] and records it in their history. */
  const setMember = (seq: number, userId: string, value: Membership | undefined): void => {
    const before = members.get(userId);
    if (before?.role === 'owner') owners -= 1;
    if (value?.role === 'owner') owners += 1;
    if (value === undefined) members.delete(userId);
    else members.set(userId, value);
    let changes = history.get(userId) as MembershipChange[] | undefined;
    if (changes === undefined || !copiedHistories.has(userId)) {
      changes = [...(changes ?? [])];
      history.set(userId, changes);
      copiedHistories.add(userId);
    }
    changes.push({ seq, membership: value });
  };

  for (const entry of entries) {
    const seq = points.length + 1;
    const fail = (reason: LogRefusal): ReplayResult => ({ ok: false, reason, failSeq: seq });

    // Chain (rule 1).
    if (entry.vaultId !== vaultId || entry.seq !== seq) return fail('broken_chain');
    if (!sameOptional(entry.previousHash, previousHash)) return fail('broken_chain');
    if (deleted) return fail('vault_deleted');
    const message = logMessage(entry);
    const hash = sha256(message);
    if (entry.entryHash !== undefined && !equalBytes(entry.entryHash, hash))
      return fail('broken_chain');

    // Who signs, with which committed keys (rule 2).
    const author = options.keysOf(entry.authorUserId, entry.authorKeyVersion);
    if (author?.userId !== entry.authorUserId) return fail('unverified_keys');
    const authorDigest = keysDigest(author);
    const subjectUserId = entry.subjectUserId === NIL_UUID ? undefined : entry.subjectUserId;
    if (entry.kind === 'vault_created' || entry.kind === 'member_keys_replaced') {
      if (
        subjectUserId !== entry.authorUserId ||
        entry.subjectKeyVersion !== entry.authorKeyVersion ||
        entry.subjectKeys === undefined ||
        !equalBytes(authorDigest, entry.subjectKeys)
      )
        return fail('unverified_keys');
    } else {
      const membership = members.get(entry.authorUserId);
      if (
        membership?.keyVersion !== entry.authorKeyVersion ||
        !equalBytes(membership.keysDigest, authorDigest)
      )
        return fail('unverified_keys');
    }
    const signatureRefusal = checkSignature(author.signingPublicKey, message, entry.signature);
    if (signatureRefusal !== undefined) return fail(signatureRefusal);
    if (options.isSuperseded?.(entry.authorUserId, entry.authorKeyVersion) === true)
      return fail('superseded_keys');

    // Requests: one author; rights from the state before the request (§7.3).
    if (request === undefined)
      request = {
        author: entry.authorUserId,
        rights: members.get(entry.authorUserId)?.role,
        kinds: [],
      };
    else if (request.author !== entry.authorUserId) return fail('bad_request_shape');
    request.kinds.push({ kind: entry.kind, self: subjectUserId === entry.authorUserId });
    const rights = request.rights;

    // Fields the kind sets (rule 3).
    const hasCheckpoint = !isAbsent(entry.checkpoint);
    const hasSubjectKeys = !isAbsent(entry.subjectKeys);
    const present: Record<Field, boolean> = {
      subject: subjectUserId !== undefined,
      role: entry.role !== undefined,
      subjectKeys: hasSubjectKeys,
      keyCommitment: !isAbsent(entry.keyCommitment),
      node: entry.nodeId !== undefined && entry.nodeId !== NIL_UUID,
      home: entry.homeVaultId !== undefined && entry.homeVaultId !== NIL_UUID,
      nodeKey: entry.nodeKey !== undefined && entry.nodeKey !== '',
      sections: entry.sections !== undefined && entry.sections !== '',
    };
    const wanted: readonly Field[] = KIND_FIELDS[entry.kind];
    const fieldsMatch =
      (Object.keys(present) as Field[]).every(
        (field) => present[field] === wanted.includes(field),
      ) &&
      hasSubjectKeys === (entry.subjectKeyVersion !== undefined && entry.subjectKeyVersion > 0);

    const subject = subjectUserId === undefined ? undefined : members.get(subjectUserId);
    const committed =
      subject !== undefined &&
      entry.subjectKeys !== undefined &&
      equalBytes(subject.keysDigest, entry.subjectKeys) &&
      subject.keyVersion === entry.subjectKeyVersion;

    switch (entry.kind) {
      case 'vault_created': {
        if (seq !== 1 || entry.role !== 'owner' || entry.keyVersion !== 1 || hasCheckpoint)
          return fail('bad_request_shape');
        if (!fieldsMatch) return fail('unexpected_field');
        setMember(seq, entry.authorUserId, membership('owner', entry));
        keyVersion = 1;
        commitments.set(1, required(entry.keyCommitment));
        break;
      }
      case 'member_added': {
        if (!fieldsMatch || hasCheckpoint) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        if (subjectUserId === undefined || subject !== undefined) return fail('invalid_entry');
        const role = required(entry.role);
        if (!roleIncludes(rights, role === 'owner' ? 'owner' : 'admin'))
          return fail('not_authorized');
        const keys = options.keysOf(subjectUserId, required(entry.subjectKeyVersion));
        if (keys === undefined || !equalBytes(keysDigest(keys), required(entry.subjectKeys)))
          return fail('unverified_keys');
        setMember(seq, subjectUserId, membership(role, entry));
        break;
      }
      case 'member_role_set': {
        if (!fieldsMatch) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        const role = required(entry.role);
        if (subjectUserId === undefined || !committed || subject.role === role)
          return fail('invalid_entry');
        const lowersSelf =
          subjectUserId === entry.authorUserId && ROLE_CODE[role] < ROLE_CODE[subject.role];
        const needed = subject.role === 'owner' || role === 'owner' ? 'owner' : 'admin';
        if (!lowersSelf && !roleIncludes(rights, needed)) return fail('not_authorized');
        const losesWrite = roleIncludes(subject.role, 'editor') && !roleIncludes(role, 'editor');
        if (losesWrite && !hasCheckpoint) return fail('missing_checkpoint');
        if (!losesWrite && hasCheckpoint) return fail('unexpected_field');
        setMember(seq, subjectUserId, { ...subject, role });
        if (owners === 0) return fail('no_owner');
        break;
      }
      case 'member_removed': {
        if (!fieldsMatch) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        if (subjectUserId === undefined || !committed) return fail('invalid_entry');
        if (subjectUserId === entry.authorUserId) {
          const needsCheckpoint = roleIncludes(subject.role, 'editor');
          if (needsCheckpoint && !hasCheckpoint) return fail('missing_checkpoint');
          if (!needsCheckpoint && hasCheckpoint) return fail('unexpected_field');
        } else {
          if (hasCheckpoint) return fail('unexpected_field');
          if (!roleIncludes(rights, subject.role === 'owner' ? 'owner' : 'admin'))
            return fail('not_authorized');
        }
        setMember(seq, subjectUserId, undefined);
        if (owners === 0) return fail('no_owner');
        // A share ends when its owner stops being a member (§7.7).
        for (const [nodeId, share] of shares) {
          if (share.ownerUserId !== subjectUserId) continue;
          shares.delete(nodeId);
          placesChangedAt = seq;
        }
        if (subjectUserId === entry.authorUserId) departed.add(subjectUserId);
        break;
      }
      case 'member_keys_replaced': {
        if (!fieldsMatch) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        const current = members.get(entry.authorUserId);
        if (current === undefined) return fail('invalid_entry');
        const newVersion = required(entry.subjectKeyVersion);
        if (newVersion <= current.keyVersion) return fail('unverified_keys');
        // Every version between the committed one and the new one must be trusted, which only a
        // verified chain of key statements gives (§5.2); the committed version must be the start.
        const start = options.keysOf(entry.authorUserId, current.keyVersion);
        if (start === undefined || !equalBytes(keysDigest(start), current.keysDigest))
          return fail('unverified_keys');
        for (let version = current.keyVersion + 1; version <= newVersion; version += 1) {
          if (options.keysOf(entry.authorUserId, version) === undefined)
            return fail('unverified_keys');
        }
        const needsCheckpoint = roleIncludes(current.role, 'editor');
        if (needsCheckpoint && !hasCheckpoint) return fail('missing_checkpoint');
        if (!needsCheckpoint && hasCheckpoint) return fail('unexpected_field');
        setMember(seq, entry.authorUserId, membership(current.role, entry));
        recordedKeyVersions.set(
          entry.authorUserId,
          Math.max(recordedKeyVersions.get(entry.authorUserId) ?? 0, newVersion),
        );
        replacedKeys.add(entry.authorUserId);
        break;
      }
      case 'key_rotated': {
        if (!fieldsMatch) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion + 1) return fail('bad_request_shape');
        if (!hasCheckpoint) return fail('missing_checkpoint');
        if (!roleIncludes(rights, 'admin')) return fail('not_authorized');
        keyVersion += 1;
        commitments.set(keyVersion, required(entry.keyCommitment));
        departed.clear();
        replacedKeys.clear();
        break;
      }
      case 'node_created': {
        if (!fieldsMatch || hasCheckpoint) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        const nodeId = required(entry.nodeId);
        const nodeKey = required(entry.nodeKey);
        if (!isValidNodeKey(nodeKey) || nodes.has(nodeId)) return fail('invalid_entry');
        const origin = { ownerUserId: entry.authorUserId, homeVaultId: vaultId, nodeKey };
        if (!roleIncludes(rights, 'editor') || !derivesNode(nodeId, origin))
          return fail('not_authorized');
        nodes.set(nodeId, { ownerUserId: entry.authorUserId, nodeKey, seq });
        placesChangedAt = seq;
        break;
      }
      case 'node_shared': {
        if (!fieldsMatch || hasCheckpoint) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        const scope = parseSectionScope(entry.sections);
        const origin = {
          ownerUserId: entry.authorUserId,
          homeVaultId: required(entry.homeVaultId),
          nodeKey: required(entry.nodeKey),
        };
        if (
          scope === undefined ||
          origin.homeVaultId === vaultId ||
          !isValidNodeKey(origin.nodeKey)
        )
          return fail('invalid_entry');
        const nodeId = required(entry.nodeId);
        const before = shares.get(nodeId);
        const names = new Map(before?.names ?? []);
        let all = before?.all;
        if (scope === '*') all ??= seq;
        else
          for (const name of scope) if (all === undefined && !names.has(name)) names.set(name, seq);
        if (names.size > MAX_SHARED_NAMES) return fail('invalid_entry');
        // Only the owner, whose id the node derives from, may say where it may be read.
        if (!roleIncludes(rights, 'admin') || !derivesNode(nodeId, origin))
          return fail('not_authorized');
        shares.set(nodeId, { ...origin, all, names });
        placesChangedAt = seq;
        break;
      }
      case 'node_unshared': {
        if (!fieldsMatch || hasCheckpoint) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        const scope = parseSectionScope(entry.sections);
        const nodeId = required(entry.nodeId);
        const share = shares.get(nodeId);
        if (scope === undefined || share === undefined) return fail('invalid_entry');
        if (!roleIncludes(rights, 'admin') && entry.authorUserId !== share.ownerUserId)
          return fail('not_authorized');
        placesChangedAt = seq;
        if (scope === '*') {
          shares.delete(nodeId);
          break;
        }
        if (share.all !== undefined || scope.some((name) => !share.names.has(name)))
          return fail('invalid_entry');
        const names = new Map(share.names);
        for (const name of scope) names.delete(name);
        if (names.size === 0) shares.delete(nodeId);
        else shares.set(nodeId, { ...share, names });
        break;
      }
      case 'vault_deleted': {
        if (!fieldsMatch || hasCheckpoint) return fail('unexpected_field');
        if (seq === 1 || entry.keyVersion !== keyVersion) return fail('bad_request_shape');
        if (!roleIncludes(rights, 'owner')) return fail('not_authorized');
        deleted = true;
        break;
      }
    }

    if (hasCheckpoint) {
      const root = required(entry.checkpoint);
      if (
        entry.checkpointLeaves !== undefined &&
        !equalBytes(checkpointRoot(entry.checkpointLeaves), root)
      )
        return fail('bad_checkpoint');
      checkpoints.push({ seq, root });
    }

    if (entry.requestEnd) {
      if (!isAllowedShape(request.kinds)) return fail('bad_request_shape');
      request = undefined;
    }

    previousHash = hash;
    points.push({
      seq,
      hash,
      // `vault_deleted` is no head: nothing may cite it (§12.3).
      head: entry.requestEnd && entry.kind !== 'vault_deleted',
      keyVersion,
      authorUserId: entry.authorUserId,
      authorKeyVersion: entry.authorKeyVersion,
    });
  }

  if (request !== undefined)
    return { ok: false, reason: 'unfinished_request', failSeq: points.length };
  if (points.length === 0) return { ok: false, reason: 'broken_chain', failSeq: 1 };
  return {
    ok: true,
    state: {
      vaultId,
      points,
      members,
      history,
      checkpoints,
      commitments,
      recordedKeyVersions,
      sinceRotation: { departed: [...departed], replacedKeys: [...replacedKeys] },
      nodes,
      shares,
      deleted,
      placesChangedAt,
    },
  };
}

/**
 * A user's membership right after entry [seq]: what a write citing that head is judged by
 * (`PROTOCOL.md` §8.4).
 *
 * @param state A verified log.
 * @param userId The user.
 * @param seq An entry of the log.
 * @returns The membership, or `undefined` when the user was not a member then.
 */
export function membershipAt(
  state: VaultLogState,
  userId: string,
  seq: number,
): Membership | undefined {
  const changes = state.history.get(userId);
  if (changes === undefined) return undefined;
  // The last change at or before [seq], by binary search over changes in log order.
  let low = 0;
  let high = changes.length - 1;
  let found: MembershipChange | undefined;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const change = changes[middle];
    if (change === undefined) break;
    if (change.seq <= seq) {
      found = change;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return found?.membership;
}

/**
 * The verified head of a log state.
 *
 * @param state A verified log.
 * @returns Its last entry.
 */
export function logHead(state: VaultLogState): LogPoint {
  const head = state.points.at(-1);
  if (head === undefined) throw new RangeError('A verified log has at least one entry');
  return head;
}

/** Tells whether a request's kinds form one of §7.3's shapes. */
function isAllowedShape(
  kinds: readonly { readonly kind: LogEntryKind; readonly self: boolean }[],
): boolean {
  const last = kinds.at(-1);
  if (last === undefined) return false;
  if (
    kinds.length === 1 &&
    (SINGLE_KINDS.has(last.kind) || (last.kind === 'member_removed' && last.self))
  )
    return true;
  return (
    last.kind === 'key_rotated' &&
    kinds.slice(0, -1).every((step) => step.kind === 'member_removed' && !step.self)
  );
}

/** A membership at the entry's subject keys. */
function membership(role: Role, entry: LogEntryFields): Membership {
  return {
    role,
    keyVersion: required(entry.subjectKeyVersion),
    keysDigest: required(entry.subjectKeys),
  };
}

/** Whether two optional digests are equal, absent meaning zero. */
function sameOptional(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (isAbsent(a) || isAbsent(b)) return isAbsent(a) && isAbsent(b);
  return a !== undefined && b !== undefined && equalBytes(a, b);
}

/** A value the field checks have already shown to be present. */
function required<T>(value: T | undefined): T {
  if (value === undefined) throw new RangeError('A checked field is missing');
  return value;
}
