import { sha256 } from '@noble/hashes/sha2.js';

import { CloakCryptoError, isCloakCryptoError } from './CloakCryptoError.ts';
import { decryptBlob, encryptBlob } from './blobs.ts';
import { equalBytes } from './bytes.ts';
import { Canonical } from './canonical.ts';
import type { CheckpointLeaf } from './checkpoints.ts';
import { LABELS } from './labels.ts';
import {
  membershipAt,
  sharedSince,
  type CheckpointRecord,
  type VaultLogState,
} from './logReplay.ts';
import { derivesNode } from './nodes.ts';
import { pad, unpad } from './padding.ts';
import { keysDigest, type PublicKeys } from './publicKeys.ts';
import { checkSignature, sign, type SignatureRefusal } from './signatures.ts';
import { contentKey, keyCommitment } from './vaultKeys.ts';
import { roleIncludes } from './vaultLog.ts';

/** Where a section's content belongs; bound into its associated data (`PROTOCOL.md` §8.1). */
export interface SectionAddress {
  /** Vault the section lives in. */
  readonly vaultId: string;
  /** Node of the section. */
  readonly nodeId: string;
  /** Section name. */
  readonly sectionName: string;
  /** Vault key version that encrypts the content. */
  readonly vaultKeyVersion: number;
}

/** The fields of a section write's signed message (`PROTOCOL.md` §8.2). */
export interface SectionWriteFields extends SectionAddress {
  /** App-defined node type. */
  readonly nodeType: string;
  /** The node's home vault (`PROTOCOL.md` §8.1). */
  readonly homeVaultId: string;
  /** The node's owner, who created it. */
  readonly ownerUserId: string;
  /** The node's key, chosen by the application. */
  readonly nodeKey: string;
  /** 1 for the first write, then one more for each later one, deletions included. */
  readonly dataVersion: number;
  /** Whether the write deletes the section; a deletion has no ciphertext. */
  readonly deleted: boolean;
  /** Sequence number of the log head the writer verified right before writing. */
  readonly logSeq: number;
  /** `entryHash` of that head. */
  readonly logHeadHash: Uint8Array;
  /** `writeHash` of the section's previous write; absent for the first. */
  readonly previousWriteHash?: Uint8Array | undefined;
  /** Writer. */
  readonly writerUserId: string;
  /** The writer's identity key version that signs. */
  readonly writerKeyVersion: number;
  /** Section ciphertext; absent for a deletion. */
  readonly ciphertext?: Uint8Array | undefined;
}

/** A section write as a member reads it. */
export interface SectionWrite extends SectionWriteFields {
  /** The writer's signature over {@link sectionWriteMessage}. */
  readonly signature: Uint8Array;
}

/**
 * A write's signed fields with the ciphertext's digest in place of the ciphertext
 * (`PROTOCOL.md` §8.2): enough to check the signature and the write's standing.
 */
export interface SectionHeaderFields extends Omit<SectionWriteFields, 'ciphertext'> {
  /** `SHA-256(ciphertext)`; absent for a deletion. */
  readonly ciphertextHash?: Uint8Array | undefined;
}

/** A write's header as a member reads it. */
export interface SectionHeader extends SectionHeaderFields {
  /** The writer's signature. */
  readonly signature: Uint8Array;
}

/**
 * The digest a header carries in place of the ciphertext.
 *
 * @param ciphertext Section ciphertext.
 * @returns `SHA-256(ciphertext)`.
 */
export function sectionCiphertextHash(ciphertext: Uint8Array): Uint8Array {
  return sha256(ciphertext);
}

/**
 * The header of a write: its fields with the ciphertext replaced by its digest.
 *
 * @param write Write fields.
 * @returns The header fields.
 */
export function toSectionHeader<T extends SectionWriteFields>(
  write: T,
): Omit<T, 'ciphertext'> & SectionHeaderFields {
  const { ciphertext, ...rest } = write;
  return {
    ...rest,
    ...(ciphertext === undefined ? {} : { ciphertextHash: sectionCiphertextHash(ciphertext) }),
  };
}

/**
 * Builds the associated data of section content, so the server cannot move ciphertext to another
 * vault, section or key version.
 *
 * @param address Vault, node, section and key version.
 * @returns Canonical associated data.
 */
export function sectionContentAd(address: SectionAddress): Uint8Array {
  return Canonical.of(LABELS.sectionContent)
    .uuid(address.vaultId)
    .uuid(address.nodeId)
    .str(address.sectionName)
    .u32(address.vaultKeyVersion)
    .build();
}

/**
 * Pads and encrypts section content with the vault's content key.
 *
 * @param vaultKey Vault key at [address].vaultKeyVersion.
 * @param address Where the content belongs.
 * @param content Application bytes, typically UTF-8 JSON.
 * @param nonce Fixed nonce for tests; random by default.
 * @returns The section ciphertext.
 */
export function encryptSection(
  vaultKey: Uint8Array,
  address: SectionAddress,
  content: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  return encryptBlob(
    contentKey(vaultKey, address.vaultId),
    sectionContentAd(address),
    pad(content),
    nonce,
  );
}

/**
 * Decrypts and unpads section content.
 *
 * @param vaultKey Vault key at [address].vaultKeyVersion.
 * @param address Where the server says the content belongs.
 * @param ciphertext Section ciphertext.
 * @returns The application bytes.
 * @throws {CloakCryptoError} `decryption_failed` when the key or address is wrong; `bad_padding`
 *   when the content was not padded.
 */
export function decryptSection(
  vaultKey: Uint8Array,
  address: SectionAddress,
  ciphertext: Uint8Array,
): Uint8Array {
  return unpad(
    decryptBlob(contentKey(vaultKey, address.vaultId), sectionContentAd(address), ciphertext),
  );
}

/**
 * Builds the message a writer signs.
 *
 * @param write Write fields.
 * @returns Canonical message.
 */
export function sectionWriteMessage(write: SectionWriteFields): Uint8Array {
  return sectionHeaderMessage(toSectionHeader(write));
}

/**
 * Builds the signed message from a header; equal to {@link sectionWriteMessage} of the write.
 *
 * @param header Header fields.
 * @returns Canonical message.
 */
export function sectionHeaderMessage(header: SectionHeaderFields): Uint8Array {
  const write = header;
  return Canonical.of(LABELS.sectionWrite)
    .uuid(write.vaultId)
    .uuid(write.nodeId)
    .str(write.nodeType)
    .uuid(write.homeVaultId)
    .uuid(write.ownerUserId)
    .str(write.nodeKey)
    .str(write.sectionName)
    .u32(write.vaultKeyVersion)
    .u64(write.dataVersion)
    .flag(write.deleted)
    .u64(write.logSeq)
    .digest32(write.logHeadHash)
    .digest32(write.previousWriteHash)
    .uuid(write.writerUserId)
    .u32(write.writerKeyVersion)
    .digest32(write.ciphertextHash)
    .build();
}

/**
 * Hashes a write into its `writeHash`, which the next write and checkpoints refer to.
 *
 * @param write Write fields.
 * @returns `SHA-256(sectionWrite)`.
 */
export function writeHash(write: SectionWriteFields): Uint8Array {
  return sha256(sectionWriteMessage(write));
}

/**
 * Hashes a header into the write's `writeHash`.
 *
 * @param header Header fields.
 * @returns `SHA-256(sectionWrite)`.
 */
export function headerWriteHash(header: SectionHeaderFields): Uint8Array {
  return sha256(sectionHeaderMessage(header));
}

/**
 * Signs a write.
 *
 * @param write Write fields.
 * @param signingSeed Seed of the writer's signing key of `writerKeyVersion`.
 * @returns The signature blob.
 */
export function signSectionWrite(write: SectionWriteFields, signingSeed: Uint8Array): Uint8Array {
  return sign(signingSeed, sectionWriteMessage(write));
}

/**
 * Why a write does not stand (`PROTOCOL.md` §8.4 rules 1 to 4 and 6):
 *
 * - `not_a_head`: `logSeq` is not a head of the verified log;
 * - `fork`: the log has another hash at `logSeq`, or the latest checkpoint holds another write of
 *   the same `dataVersion`;
 * - `wrong_key_version`: `vaultKeyVersion` is not the vault's key version at `logSeq`;
 * - `bad_deletion`: a deletion with a ciphertext, or a write without;
 * - `not_an_editor`: the writer's keys were not committed for an editor at `logSeq`;
 * - `superseded_keys`: the writer signs with a key version the reader knows was replaced;
 * - a {@link SignatureRefusal}: the signature does not verify;
 * - `vault_deleted`: the vault's log ends in its deletion, after which no write stands;
 * - `bad_node`: the node id does not derive from the write's owner, home vault and key;
 * - `not_shared`: the node does not live in the vault since the write's head: it was not created
 *   there, or the vault does not share the section's name;
 * - `not_in_checkpoint`: a checkpoint follows `logSeq` and does not hold the write;
 * - `rollback`: the latest checkpoint after `logSeq` holds a newer write of the section.
 */
export type StandingRefusal =
  | 'not_a_head'
  | 'fork'
  | 'wrong_key_version'
  | 'bad_deletion'
  | 'not_an_editor'
  | 'superseded_keys'
  | SignatureRefusal
  | 'vault_deleted'
  | 'bad_node'
  | 'not_shared'
  | 'not_in_checkpoint'
  | 'rollback';

/**
 * Why a standing write's content is refused:
 *
 * - `bad_ciphertext`: the ciphertext does not hash to the signed `ciphertextHash`;
 * - `key_mismatch`: the vault key given does not match the log's commitment;
 * - `decryption_failed`, `bad_padding`: the content does not open.
 */
export type ContentRefusal =
  'bad_ciphertext' | 'key_mismatch' | 'decryption_failed' | 'bad_padding';

/** Why a write is refused, for its standing or its content. */
export type WriteRefusal = StandingRefusal | ContentRefusal;

/** Outcome of judging a write's standing. */
export type StandingCheck =
  | {
      /** Discriminant. */
      readonly ok: true;
      /** The write's `writeHash`. */
      readonly writeHash: Uint8Array;
    }
  | {
      /** Discriminant. */
      readonly ok: false;
      /** Why it does not stand. */
      readonly reason: StandingRefusal;
    };

/** Outcome of opening a write's content. */
export type ContentCheck =
  | {
      /** Discriminant. */
      readonly ok: true;
      /** Decrypted content; absent for a deletion. */
      readonly content?: Uint8Array | undefined;
    }
  | {
      /** Discriminant. */
      readonly ok: false;
      /** Why the content is refused. */
      readonly reason: ContentRefusal;
    };

/** The checkpoints a write is judged by: those after its `logSeq` (`PROTOCOL.md` §8.4 rule 4). */
export interface WriteCheckpoints {
  /** The first checkpoint after `logSeq`; absent when none follows. */
  readonly first?: CheckpointRecord | undefined;
  /** The latest checkpoint after `logSeq`; absent when none follows. */
  readonly latest?: CheckpointRecord | undefined;
}

/**
 * The checkpoints that follow a head in a verified log.
 *
 * @param log The verified log.
 * @param logSeq The head a write cites.
 * @returns The first and the latest checkpoint after it.
 */
export function checkpointsAfter(log: VaultLogState, logSeq: number): WriteCheckpoints {
  const later = log.checkpoints.filter((checkpoint) => checkpoint.seq > logSeq);
  return { first: later[0], latest: later.at(-1) };
}

/** What judging a write's standing needs besides the verified log. */
export interface StandingOptions {
  /** Trusted public keys of a user's key version, as for the log. */
  readonly keysOf: (userId: string, keyVersion: number) => PublicKeys | undefined;
  /** Whether the reader knows a later version of the user's keys. */
  readonly isSuperseded?: ((userId: string, keyVersion: number) => boolean) | undefined;
  /**
   * What each checkpoint of {@link checkpointsAfter} holds for the write's section, keyed by the
   * checkpoint's `seq`, as the caller verified against its root (a proof or the whole leaf list):
   * the leaf, or `undefined` when the checkpoint does not hold the section. Every checkpoint of
   * `checkpointsAfter` must be present.
   */
  readonly checkpointLeaves: ReadonlyMap<number, CheckpointLeaf | undefined>;
  /**
   * Whether the reader already verified this very header's signature against the same keys, such
   * as for a write it keeps from an earlier read (`PROTOCOL.md` §15). A signature never changes, so
   * it is not checked again; every other rule is.
   */
  readonly signatureVerified?: boolean | undefined;
}

/**
 * Judges a write's standing from its header (`PROTOCOL.md` §8.4 rules 1 to 4); rule 5, order, is
 * {@link checkSectionOrder}. The caller has already continued the log to `logSeq` when it can.
 *
 * @param header The write's header, as served or computed from the write.
 * @param log The verified log of the write's vault.
 * @param options Keys and what the checkpoints after `logSeq` hold.
 * @returns The `writeHash` of a standing write, or why it does not stand.
 * @throws {RangeError} when `checkpointLeaves` lacks a checkpoint the write is judged by.
 */
export function verifySectionStanding(
  header: SectionHeader,
  log: VaultLogState,
  options: StandingOptions,
): StandingCheck {
  const refuse = (reason: StandingRefusal): StandingCheck => ({ ok: false, reason });
  if (header.vaultId !== log.vaultId) return refuse('not_a_head');
  if (log.deleted) return refuse('vault_deleted');

  // Head (rule 1) and key version (rule 2).
  const point = log.points[header.logSeq - 1];
  if (point?.head !== true) return refuse('not_a_head');
  if (!equalBytes(point.hash, header.logHeadHash)) return refuse('fork');
  if (header.vaultKeyVersion !== point.keyVersion) return refuse('wrong_key_version');
  if (header.deleted !== (header.ciphertextHash === undefined)) return refuse('bad_deletion');

  // Writer (rule 3).
  const writer = options.keysOf(header.writerUserId, header.writerKeyVersion);
  const membership = membershipAt(log, header.writerUserId, header.logSeq);
  if (
    writer === undefined ||
    membership?.keyVersion !== header.writerKeyVersion ||
    !equalBytes(membership.keysDigest, keysDigest(writer)) ||
    !roleIncludes(membership.role, 'editor')
  )
    return refuse('not_an_editor');
  const message = sectionHeaderMessage(header);
  if (options.signatureVerified !== true) {
    const signatureRefusal = checkSignature(writer.signingPublicKey, message, header.signature);
    if (signatureRefusal !== undefined) return refuse(signatureRefusal);
  }
  if (options.isSuperseded?.(header.writerUserId, header.writerKeyVersion) === true)
    return refuse('superseded_keys');

  // Place (rule 6): every write names its node truthfully; one with content stands only where the
  // node lives, as the owner's entries recorded it. A deletion carries nothing to read.
  if (!derivesNode(header.nodeId, header)) return refuse('bad_node');
  if (!header.deleted && !livesHere(header, log)) return refuse('not_shared');

  // Checkpoints (rule 4): in the first after `logSeq`, and the very leaf of the latest.
  const hash = sha256(message);
  const { first, latest } = checkpointsAfter(log, header.logSeq);
  const held = (checkpoint: CheckpointRecord): CheckpointLeaf | undefined => {
    if (!options.checkpointLeaves.has(checkpoint.seq))
      throw new RangeError(`What checkpoint ${String(checkpoint.seq)} holds is not given`);
    return options.checkpointLeaves.get(checkpoint.seq);
  };
  const isThisWrite = (leaf: CheckpointLeaf | undefined): boolean =>
    leaf?.nodeId === header.nodeId &&
    leaf.sectionName === header.sectionName &&
    leaf.dataVersion === header.dataVersion &&
    equalBytes(leaf.writeHash, hash);
  if (header.deleted) {
    // A deletion is never a leaf (§7.5): every checkpoint after its head must hold none for the
    // section. A higher version there means a later write superseded it; any other leaf shows the
    // deletion was not in effect when that checkpoint was taken.
    for (const checkpoint of [first, latest]) {
      const leaf = checkpoint === undefined ? undefined : held(checkpoint);
      if (leaf === undefined) continue;
      return refuse(leaf.dataVersion > header.dataVersion ? 'rollback' : 'not_in_checkpoint');
    }
    return { ok: true, writeHash: hash };
  }
  if (first !== undefined && !isThisWrite(held(first))) return refuse('not_in_checkpoint');
  if (latest !== undefined && latest !== first) {
    const leaf = held(latest);
    if (leaf === undefined) return refuse('not_in_checkpoint');
    if (leaf.dataVersion > header.dataVersion) return refuse('rollback');
    if (!isThisWrite(leaf)) return refuse('fork');
  }
  return { ok: true, writeHash: hash };
}

/**
 * Whether a write's node lives in its vault since no later than the write's head (`PROTOCOL.md`
 * §7.7): created there, its home, or shared there by name or whole, with the owner, home and key
 * the entry recorded.
 */
function livesHere(header: SectionHeaderFields, log: VaultLogState): boolean {
  if (header.homeVaultId === header.vaultId) {
    const node = log.nodes.get(header.nodeId);
    return (
      node?.ownerUserId === header.ownerUserId &&
      node.nodeKey === header.nodeKey &&
      node.seq <= header.logSeq
    );
  }
  const share = log.shares.get(header.nodeId);
  const since = sharedSince(log, header.nodeId, header.sectionName);
  return (
    share?.ownerUserId === header.ownerUserId &&
    share.homeVaultId === header.homeVaultId &&
    share.nodeKey === header.nodeKey &&
    since !== undefined &&
    since <= header.logSeq
  );
}

/**
 * Opens the content of a write whose standing was checked (`PROTOCOL.md` §8.4).
 *
 * @param write The write with its ciphertext.
 * @param log The verified log of the write's vault.
 * @param vaultKey The vault key of `vaultKeyVersion`, when the reader holds it.
 * @param ciphertextHash The signed digest from the write's header.
 * @returns The content, absent for a deletion, or why it is refused.
 */
export function openSectionContent(
  write: SectionWriteFields,
  log: VaultLogState,
  vaultKey: Uint8Array | undefined,
  ciphertextHash: Uint8Array | undefined,
): ContentCheck {
  const refuse = (reason: ContentRefusal): ContentCheck => ({ ok: false, reason });
  if (write.ciphertext === undefined) {
    return ciphertextHash === undefined ? { ok: true } : refuse('bad_ciphertext');
  }
  if (
    ciphertextHash === undefined ||
    !equalBytes(sectionCiphertextHash(write.ciphertext), ciphertextHash)
  )
    return refuse('bad_ciphertext');
  const committed = log.commitments.get(write.vaultKeyVersion);
  if (
    vaultKey === undefined ||
    committed === undefined ||
    !equalBytes(keyCommitment(vaultKey, write.vaultId, write.vaultKeyVersion), committed)
  )
    return refuse('key_mismatch');
  try {
    return { ok: true, content: decryptSection(vaultKey, write, write.ciphertext) };
  } catch (error: unknown) {
    if (isCloakCryptoError(error) && error.code === 'bad_padding') return refuse('bad_padding');
    if (isCloakCryptoError(error)) return refuse('decryption_failed');
    throw error;
  }
}

/** What a device remembers of a section (`PROTOCOL.md` §15). */
export interface SectionMark {
  /** Highest `dataVersion` seen. */
  readonly dataVersion: number;
  /** `writeHash` of that write. */
  readonly writeHash: Uint8Array;
}

/**
 * Checks a write against what this device has seen of the section (`PROTOCOL.md` §8.4 rule 5).
 *
 * @param mark What the device has seen; absent when it has seen nothing.
 * @param write The write, with its `writeHash`.
 * @returns `undefined` when the write may be shown, `rollback` when it is behind, `fork` when it
 *   has the same version and another hash or does not chain to the one seen.
 */
export function checkSectionOrder(
  mark: SectionMark | undefined,
  write: Pick<SectionWriteFields, 'dataVersion' | 'previousWriteHash'> & {
    readonly writeHash: Uint8Array;
  },
): 'rollback' | 'fork' | undefined {
  if (mark === undefined) return undefined;
  if (write.dataVersion < mark.dataVersion) return 'rollback';
  if (write.dataVersion === mark.dataVersion)
    return equalBytes(write.writeHash, mark.writeHash) ? undefined : 'fork';
  if (
    write.dataVersion === mark.dataVersion + 1 &&
    (write.previousWriteHash === undefined || !equalBytes(write.previousWriteHash, mark.writeHash))
  )
    return 'fork';
  return undefined;
}

/**
 * Fails unless a ciphertext has a valid section size: 41 + 256·n bytes, n ≥ 1, at most 1 MiB.
 *
 * @param ciphertext Section ciphertext.
 * @throws {CloakCryptoError} `invalid_format` otherwise.
 */
export function requireSectionSize(ciphertext: Uint8Array): void {
  const body = ciphertext.length - 41;
  if (body < 256 || body % 256 !== 0 || ciphertext.length > 1_048_576) {
    throw new CloakCryptoError('invalid_format', 'Section ciphertext has an invalid size');
  }
}
