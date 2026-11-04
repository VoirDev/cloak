import { sha256 } from '@noble/hashes/sha2.js';

import { Canonical } from './canonical.ts';
import { LABELS } from './labels.ts';
import { sign } from './signatures.ts';

/** Role in a vault, weakest first; each role includes every weaker one. */
export type Role = 'viewer' | 'editor' | 'admin' | 'owner';

/** Kind of a vault log entry (`PROTOCOL.md` §7.2). */
export type LogEntryKind =
  | 'vault_created'
  | 'member_added'
  | 'member_role_set'
  | 'member_removed'
  | 'member_keys_replaced'
  | 'key_rotated'
  | 'node_created'
  | 'node_shared'
  | 'node_unshared'
  | 'vault_deleted';

/** Role codes of the canonical encoding (`PROTOCOL.md` §3); the order is the strength. */
export const ROLE_CODE = { viewer: 1, editor: 2, admin: 3, owner: 4 } as const satisfies Record<
  Role,
  number
>;

/** Kind codes of the canonical encoding (`PROTOCOL.md` §3). */
export const KIND_CODE = {
  vault_created: 1,
  member_added: 2,
  member_role_set: 3,
  member_removed: 4,
  member_keys_replaced: 5,
  key_rotated: 6,
  node_created: 7,
  node_shared: 8,
  node_unshared: 9,
  vault_deleted: 10,
} as const satisfies Record<LogEntryKind, number>;

/** The fields of a vault log entry's signed message (`PROTOCOL.md` §7.1). */
export interface LogEntryFields {
  /** Vault whose log the entry extends. */
  readonly vaultId: string;
  /** Position in the log, from 1. */
  readonly seq: number;
  /** `entryHash` of the previous entry; absent for `seq` 1. */
  readonly previousHash?: Uint8Array | undefined;
  /** Kind of entry. */
  readonly kind: LogEntryKind;
  /** User subject, if the kind takes one. */
  readonly subjectUserId?: string | undefined;
  /** Role set, if the kind takes one. */
  readonly role?: Role | undefined;
  /** Vault key version once the entry applies. */
  readonly keyVersion: number;
  /** `keysDigest` of the subject's keys; absent without a subject. */
  readonly subjectKeys?: Uint8Array | undefined;
  /** The subject's identity key version; absent with {@link LogEntryFields.subjectKeys}. */
  readonly subjectKeyVersion?: number | undefined;
  /** Commitment of the key version the entry creates. */
  readonly keyCommitment?: Uint8Array | undefined;
  /** Merkle root over the vault's latest writes, where §7.5 requires one. */
  readonly checkpoint?: Uint8Array | undefined;
  /** Whether this is the last entry of its request, a head a write may cite. */
  readonly requestEnd: boolean;
  /** Author, who signs. */
  readonly authorUserId: string;
  /** The author's identity key version that signs. */
  readonly authorKeyVersion: number;
  /** Node a node entry creates, shares or takes back (`PROTOCOL.md` §7.7). */
  readonly nodeId?: string | undefined;
  /** Home vault of the node `node_shared` shares. */
  readonly homeVaultId?: string | undefined;
  /** Key of the node `node_created` creates or `node_shared` shares. */
  readonly nodeKey?: string | undefined;
  /** Names a node entry covers: `*`, or names ascending and comma-joined. */
  readonly sections?: string | undefined;
}

/**
 * Tells whether one role includes another.
 *
 * @param role Role held, or `undefined` for none.
 * @param needed Role required.
 * @returns `true` when [role] is [needed] or stronger.
 */
export function roleIncludes(role: Role | undefined, needed: Role): boolean {
  return role !== undefined && ROLE_CODE[role] >= ROLE_CODE[needed];
}

/**
 * Builds the message an author signs for a vault log entry; absent ids are the nil UUID, absent
 * digests 32 zero bytes, an absent role or version 0.
 *
 * @param entry Entry fields.
 * @returns Canonical message.
 */
export function logMessage(entry: LogEntryFields): Uint8Array {
  return Canonical.of(LABELS.vaultLog)
    .uuid(entry.vaultId)
    .u64(entry.seq)
    .digest32(entry.previousHash)
    .u8(KIND_CODE[entry.kind])
    .uuid(entry.subjectUserId)
    .u8(entry.role === undefined ? 0 : ROLE_CODE[entry.role])
    .u32(entry.keyVersion)
    .digest32(entry.subjectKeys)
    .u32(entry.subjectKeyVersion ?? 0)
    .digest32(entry.keyCommitment)
    .digest32(entry.checkpoint)
    .flag(entry.requestEnd)
    .uuid(entry.authorUserId)
    .u32(entry.authorKeyVersion)
    .uuid(entry.nodeId)
    .uuid(entry.homeVaultId)
    .str(entry.nodeKey ?? '')
    .str(entry.sections ?? '')
    .build();
}

/**
 * Hashes a log entry into its `entryHash`, which the next entry chains to.
 *
 * @param entry Entry fields.
 * @returns `SHA-256(logMessage)`.
 */
export function entryHash(entry: LogEntryFields): Uint8Array {
  return sha256(logMessage(entry));
}

/**
 * Signs a log entry.
 *
 * @param entry Entry fields.
 * @param signingSeed Seed of the author's signing key of `authorKeyVersion`.
 * @returns The signature blob.
 */
export function signLogEntry(entry: LogEntryFields, signingSeed: Uint8Array): Uint8Array {
  return sign(signingSeed, logMessage(entry));
}
