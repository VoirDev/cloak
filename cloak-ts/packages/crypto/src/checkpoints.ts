import { sha256 } from '@noble/hashes/sha2.js';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { compareBytes, concatBytes, equalBytes, isUuid, utf8, uuidBytes } from './bytes.ts';
import { Canonical, isBytes32, isStr, isU64 } from './canonical.ts';

/** A section's latest write as a checkpoint holds it (`PROTOCOL.md` §7.5). */
export interface CheckpointLeaf {
  /** Node of the section. */
  readonly nodeId: string;
  /** Section name. */
  readonly sectionName: string;
  /** Data version of the write. */
  readonly dataVersion: number;
  /** `writeHash` of the write. */
  readonly writeHash: Uint8Array;
}

/** An RFC 6962 audit path that shows one leaf in a tree. */
export interface InclusionProof {
  /** Index of the leaf, from 0. */
  readonly index: number;
  /** Number of leaves in the tree. */
  readonly size: number;
  /** Sibling hashes from the leaf up to the root. */
  readonly path: readonly Uint8Array[];
}

/** One leaf with the proof that it is in a tree. */
export interface LeafProof extends InclusionProof {
  /** The leaf. */
  readonly leaf: CheckpointLeaf;
}

/** Proof that a section is not in a checkpoint: the leaves around where it would be. */
export interface AbsenceProof {
  /** Number of leaves in the tree. */
  readonly size: number;
  /** The leaf just before the section's place; absent when the section would be first. */
  readonly before?: LeafProof | undefined;
  /** The leaf just after the section's place; absent when the section would be last. */
  readonly after?: LeafProof | undefined;
}

/**
 * Encodes a leaf's data: `uuid nodeId ‖ str sectionName ‖ u64 dataVersion ‖ digest32 writeHash`.
 *
 * @param leaf The leaf.
 * @returns Leaf data, before hashing.
 */
export function leafData(leaf: CheckpointLeaf): Uint8Array {
  return new Canonical()
    .uuid(leaf.nodeId)
    .str(leaf.sectionName)
    .u64(leaf.dataVersion)
    .digest32(leaf.writeHash)
    .build();
}

/**
 * Tells whether every field of a leaf fits its type in the canonical encoding (`PROTOCOL.md` §3),
 * so that {@link leafData} encodes it.
 *
 * @param leaf The leaf, as served.
 * @returns Whether it has leaf data.
 */
export function isWellFormedLeaf(leaf: CheckpointLeaf): boolean {
  return (
    isUuid(leaf.nodeId) &&
    isStr(leaf.sectionName) &&
    isU64(leaf.dataVersion) &&
    isBytes32(leaf.writeHash)
  );
}

/**
 * Hashes a leaf: `SHA-256(0x00 ‖ leafData)`.
 *
 * @param leaf The leaf.
 * @returns 32-byte leaf hash.
 */
export function leafHash(leaf: CheckpointLeaf): Uint8Array {
  return sha256(concatBytes(Uint8Array.of(0), leafData(leaf)));
}

/**
 * Orders sections by node id bytes, then section name bytes, the order of a checkpoint's leaves.
 *
 * @param a First section.
 * @param b Second section.
 * @returns Negative, zero or positive.
 */
export function compareSections(
  a: Pick<CheckpointLeaf, 'nodeId' | 'sectionName'>,
  b: Pick<CheckpointLeaf, 'nodeId' | 'sectionName'>,
): number {
  return (
    compareBytes(uuidBytes(a.nodeId), uuidBytes(b.nodeId)) ||
    compareBytes(utf8(a.sectionName), utf8(b.sectionName))
  );
}

/**
 * Sorts leaves into checkpoint order.
 *
 * @param leaves Leaves in any order.
 * @returns A sorted copy.
 */
export function sortLeaves(leaves: readonly CheckpointLeaf[]): readonly CheckpointLeaf[] {
  return leaves.toSorted(compareSections);
}

/**
 * Computes a checkpoint: the RFC 6962 Merkle tree hash over the leaves in checkpoint order. Its
 * author lists one leaf per live section, from a map of the latest writes, so a list that names a
 * section twice is a bug, not a checkpoint.
 *
 * @param leaves Latest writes of the vault's sections, in any order.
 * @returns The 32-byte root; `SHA-256` of nothing when there are no leaves.
 * @throws {CloakCryptoError} `invalid_format` when the leaves name a section twice (§7.5).
 */
export function checkpointRoot(leaves: readonly CheckpointLeaf[]): Uint8Array {
  const root = rootOfLeafList(leaves);
  if (root === undefined)
    throw new CloakCryptoError('invalid_format', 'A checkpoint holds one leaf per section');
  return root;
}

/**
 * Computes the root of a leaf list a reader holds, which it refuses when the list names a section
 * twice (`PROTOCOL.md` §7.5), whatever root that list gives.
 *
 * @param leaves Well-formed leaves in any order.
 * @returns The root, or `undefined` when two leaves share a node id and section name.
 */
export function rootOfLeafList(leaves: readonly CheckpointLeaf[]): Uint8Array | undefined {
  const sorted = sortLeaves(leaves);
  for (let index = 1; index < sorted.length; index += 1) {
    const previous = sorted[index - 1];
    const current = sorted[index];
    if (previous !== undefined && current !== undefined && compareSections(previous, current) === 0)
      return undefined;
  }
  return treeHash(sorted.map(leafHash));
}

/**
 * RFC 6962 §2.1 Merkle tree hash over leaf hashes, built level by level: a lone last node moves
 * up unchanged, which gives the same tree as the recursive definition in linear time.
 *
 * @param hashes Leaf hashes in order.
 * @returns The root.
 */
export function treeHash(hashes: readonly Uint8Array[]): Uint8Array {
  if (hashes.length === 0) return sha256(new Uint8Array(0));
  let level = hashes;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1];
      if (left === undefined) break;
      next.push(right === undefined ? left : nodeHash(left, right));
    }
    level = next;
  }
  const [root] = level;
  if (root === undefined) throw new RangeError('A tree has a root');
  return root;
}

/**
 * RFC 6962 §2.1.1 audit path of one leaf.
 *
 * @param index Index of the leaf.
 * @param hashes Every leaf hash in order.
 * @returns Sibling hashes from the leaf up to the root.
 */
export function auditPath(index: number, hashes: readonly Uint8Array[]): readonly Uint8Array[] {
  if (hashes.length <= 1) return [];
  const split = splitPoint(hashes.length);
  return index < split
    ? [...auditPath(index, hashes.slice(0, split)), treeHash(hashes.slice(split))]
    : [...auditPath(index - split, hashes.slice(split)), treeHash(hashes.slice(0, split))];
}

/**
 * Checks an audit path, as RFC 9162 §2.1.3.2 says.
 *
 * @param proof Index, tree size and path.
 * @param hash Hash of the leaf.
 * @param root Root the path must reach.
 * @returns Whether the leaf is at that index in the tree with that root.
 */
export function verifyInclusion(
  proof: InclusionProof,
  hash: Uint8Array,
  root: Uint8Array,
): boolean {
  const { index, size, path } = proof;
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size)
    return false;
  let fn = BigInt(index);
  let sn = BigInt(size - 1);
  let result = hash;
  for (const sibling of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      result = nodeHash(sibling, result);
      if ((fn & 1n) === 0n) {
        do {
          fn >>= 1n;
          sn >>= 1n;
        } while ((fn & 1n) === 0n && fn !== 0n);
      }
    } else {
      result = nodeHash(result, sibling);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equalBytes(result, root);
}

/**
 * Checks that a section is not in a checkpoint: the two neighbouring leaves are in it, next to
 * each other, and the section sorts strictly between them.
 *
 * @param proof The neighbours and the tree size.
 * @param section The section that should be absent.
 * @param root The checkpoint.
 * @returns Whether the proof shows the section absent.
 */
export function verifyAbsence(
  proof: AbsenceProof,
  section: Pick<CheckpointLeaf, 'nodeId' | 'sectionName'>,
  root: Uint8Array,
): boolean {
  const { before, after, size } = proof;
  if (size === 0)
    return before === undefined && after === undefined && equalBytes(root, treeHash([]));
  const holds = (leaf: LeafProof): boolean =>
    leaf.size === size && verifyInclusion(leaf, leafHash(leaf.leaf), root);
  if (before !== undefined && (!holds(before) || compareSections(before.leaf, section) >= 0))
    return false;
  if (after !== undefined && (!holds(after) || compareSections(section, after.leaf) >= 0))
    return false;
  if (before === undefined) return after?.index === 0;
  if (after === undefined) return before.index === size - 1;
  return after.index === before.index + 1;
}

/** What a checkpoint holds for one section, once its proof verified. */
export type CheckpointLookup =
  | {
      /** Discriminant: the proof verified against the root. */
      readonly verified: true;
      /** The section's leaf; absent when the checkpoint does not hold the section. */
      readonly leaf?: CheckpointLeaf | undefined;
    }
  | {
      /** Discriminant: the proof does not show what it claims. */
      readonly verified: false;
    };

/**
 * Checks a proof of what a checkpoint holds for one section (`PROTOCOL.md` §7.5): either the
 * section's own leaf, or the neighbours that show it absent.
 *
 * @param proof The leaf, or the neighbours, with the tree size.
 * @param section The section asked about.
 * @param root The signed checkpoint.
 * @returns The verified leaf or absence, or `verified: false` when the proof does not hold.
 */
export function resolveCheckpointProof(
  proof: AbsenceProof & { readonly inclusion?: LeafProof | undefined },
  section: Pick<CheckpointLeaf, 'nodeId' | 'sectionName'>,
  root: Uint8Array,
): CheckpointLookup {
  const { inclusion } = proof;
  if (inclusion !== undefined) {
    const holds =
      proof.before === undefined &&
      proof.after === undefined &&
      inclusion.size === proof.size &&
      compareSections(inclusion.leaf, section) === 0 &&
      verifyInclusion(inclusion, leafHash(inclusion.leaf), root);
    return holds ? { verified: true, leaf: inclusion.leaf } : { verified: false };
  }
  return verifyAbsence(proof, section, root) ? { verified: true } : { verified: false };
}

/** Hashes an inner node: `SHA-256(0x01 ‖ left ‖ right)`. */
function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(Uint8Array.of(1), left, right));
}

/** Largest power of two below n (n > 1). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
