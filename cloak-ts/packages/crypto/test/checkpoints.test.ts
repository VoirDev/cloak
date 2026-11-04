import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import {
  auditPath,
  checkpointRoot,
  leafData,
  leafHash,
  resolveCheckpointProof,
  sortLeaves,
  treeHash,
  verifyAbsence,
  verifyInclusion,
  type CheckpointLeaf,
  type LeafProof,
} from '../src/index.ts';
import { toLeaf } from './fixtures.ts';
import { fromHex, hex, num, objects, text, toHex, vectors } from './vectors.ts';

const CHECKPOINTS = vectors('checkpoints.json');
const TREES = objects(CHECKPOINTS, 'trees');

describe('checkpoints', () => {
  it('hashes no leaves to SHA-256 of nothing', () => {
    expect(toHex(treeHash([]))).toBe(text(CHECKPOINTS, 'emptyRoot'));
    expect(toHex(checkpointRoot([]))).toBe(text(CHECKPOINTS, 'emptyRoot'));
  });

  it.each(TREES.map((tree) => [num(tree, 'size'), tree] as const))(
    'builds the tree of %i leaves, with every audit path',
    (_, tree) => {
      const jsonLeaves = objects(tree, 'leaves');
      const leaves = jsonLeaves.map(toLeaf);
      const root = hex(tree, 'root');
      // The vectors list leaves in checkpoint order; any order must give the same root.
      expect(toHex(checkpointRoot(leaves.toReversed()))).toBe(text(tree, 'root'));
      expect(sortLeaves(leaves.toReversed())).toEqual(leaves);

      const hashes = leaves.map(leafHash);
      jsonLeaves.forEach((json, index) => {
        const leaf = leaves[index];
        const hash = hashes[index];
        if (leaf === undefined || hash === undefined) throw new Error('leaf');
        expect(toHex(leafData(leaf))).toBe(text(json, 'leafData'));
        expect(toHex(hash)).toBe(text(json, 'leafHash'));
        const path = auditPath(index, hashes);
        expect(path.map(toHex)).toEqual(json['path']);
        expect(verifyInclusion({ index, size: leaves.length, path }, hash, root)).toBe(true);
      });
    },
  );

  it.each(objects(CHECKPOINTS, 'negatives').map((json) => [text(json, 'name'), json] as const))(
    'refuses the proof %s',
    (_, json) => {
      expect(text(json, 'reason')).toBe('bad_proof');
      const proof = {
        index: num(json, 'index'),
        size: num(json, 'size'),
        path: (json['path'] as string[]).map(fromHex),
      };
      expect(verifyInclusion(proof, hex(json, 'leafHash'), hex(json, 'root'))).toBe(false);
    },
  );

  it('proves a section absent with its two neighbours, and refuses a gap', () => {
    const tree = TREES[5];
    if (tree === undefined) throw new Error('tree');
    const leaves = objects(tree, 'leaves').map(toLeaf);
    const hashes = leaves.map(leafHash);
    const root = hex(tree, 'root');
    const proofOf = (index: number): LeafProof => {
      const leaf = leaves[index];
      if (leaf === undefined) throw new Error('leaf');
      return { leaf, index, size: leaves.length, path: auditPath(index, hashes) };
    };
    const [first, second, third] = [proofOf(0), proofOf(1), proofOf(2)];
    // A section that sorts between the first and second leaves: same node as the first, later name.
    const between = { nodeId: first.leaf.nodeId, sectionName: 'zzz' };

    expect(
      verifyAbsence({ size: leaves.length, before: first, after: second }, between, root),
    ).toBe(true);
    expect(verifyAbsence({ size: leaves.length, before: first, after: third }, between, root)).toBe(
      false,
    );
    expect(
      verifyAbsence({ size: leaves.length, before: second, after: third }, between, root),
    ).toBe(false);
    expect(
      verifyAbsence(
        { size: leaves.length, after: first },
        { nodeId: '00000000-0000-0000-0000-000000000001', sectionName: 'a' },
        root,
      ),
    ).toBe(true);
    expect(
      verifyAbsence({ size: leaves.length, before: first, after: second }, first.leaf, root),
    ).toBe(false);
    expect(verifyAbsence({ size: 0 }, between, fromHex(text(CHECKPOINTS, 'emptyRoot')))).toBe(true);
  });

  it('builds the same tree level by level as the recursive definition', () => {
    const recursive = (hashes: readonly Uint8Array[]): Uint8Array => {
      if (hashes.length === 0) return treeHash([]);
      if (hashes.length === 1) return hashes[0] ?? new Uint8Array();
      let split = 1;
      while (split * 2 < hashes.length) split *= 2;
      const left = recursive(hashes.slice(0, split));
      const right = recursive(hashes.slice(split));
      return nodeOf(left, right);
    };
    for (let size = 0; size <= 300; size += size < 40 ? 1 : 13) {
      const hashes = Array.from({ length: size }, (_, index) => leafHash(leafAt(index)));
      expect(toHex(treeHash(hashes))).toBe(toHex(recursive(hashes)));
    }
  });

  it('resolves inclusion and absence proofs, and refuses ones that do not hold', () => {
    const leaves = sortLeaves(Array.from({ length: 11 }, (_, index) => leafAt(index * 2)));
    const hashes = leaves.map(leafHash);
    const root = checkpointRoot(leaves);
    const proofAt = (index: number): LeafProof => ({
      index,
      size: leaves.length,
      leaf: leaves[index] ?? leafAt(0),
      path: auditPath(index, hashes),
    });
    const fifth = leaves[5] ?? leafAt(0);

    expect(resolveCheckpointProof({ size: 11, inclusion: proofAt(5) }, fifth, root)).toEqual({
      verified: true,
      leaf: fifth,
    });
    // A leaf of another section is not the section asked about.
    expect(resolveCheckpointProof({ size: 11, inclusion: proofAt(4) }, fifth, root)).toEqual({
      verified: false,
    });
    // A gap between two neighbours shows a section absent; a gap that skips a leaf does not.
    const missing = { nodeId: fifth.nodeId, sectionName: 'zzz' };
    expect(
      resolveCheckpointProof({ size: 11, before: proofAt(5), after: proofAt(6) }, missing, root),
    ).toEqual({ verified: true });
    expect(
      resolveCheckpointProof({ size: 11, before: proofAt(5), after: proofAt(7) }, missing, root),
    ).toEqual({ verified: false });
    // Claiming a present section absent fails, and so does a proof against another root.
    expect(
      resolveCheckpointProof({ size: 11, before: proofAt(4), after: proofAt(5) }, fifth, root),
    ).toEqual({ verified: false });
    expect(
      resolveCheckpointProof({ size: 11, inclusion: proofAt(5) }, fifth, new Uint8Array(32)),
    ).toEqual({ verified: false });
    expect(
      resolveCheckpointProof({ size: 11, inclusion: { ...proofAt(5), size: 12 } }, fifth, root),
    ).toEqual({ verified: false });
  });
});

/** A leaf of a synthetic checkpoint. */
function leafAt(index: number): CheckpointLeaf {
  return {
    nodeId: `0192f5a7-0000-7000-8000-${String(Math.floor(index / 2)).padStart(12, '0')}`,
    sectionName: index % 2 === 0 ? 'general' : 'secrets',
    dataVersion: index + 1,
    writeHash: new Uint8Array(32).fill(index % 251),
  };
}

/** An inner node hash, as RFC 6962 defines it. */
function nodeOf(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(Uint8Array.from([1, ...left, ...right]));
}
