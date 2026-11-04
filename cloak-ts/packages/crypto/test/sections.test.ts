import { describe, expect, it } from 'vitest';

import {
  checkSectionOrder,
  checkpointsAfter,
  encryptSection,
  headerWriteHash,
  openSectionContent,
  replayVaultLog,
  requireSectionSize,
  resolveCheckpointProof,
  sectionHeaderMessage,
  sectionWriteMessage,
  signSectionWrite,
  toSectionHeader,
  verifySectionStanding,
  writeHash,
  type CheckpointLeaf,
  type LeafProof,
  type SectionWrite,
  type VaultLogState,
  type WriteRefusal,
} from '../src/index.ts';
import { IDENTITIES, keysOf, toLeaf, toLogEntry, toSectionWrite, vaultKeyOf } from './fixtures.ts';
import {
  child,
  fromHex,
  num,
  objects,
  text,
  toHex,
  utf8Of,
  vectors,
  type Json,
} from './vectors.ts';

const SECTIONS = vectors('sections.json');
const LOG = vectors('vault-log.json');
const CASES = objects(SECTIONS, 'cases');

/** The verified scenario log. */
function scenarioLog(): VaultLogState {
  const result = replayVaultLog(text(LOG, 'vaultId'), objects(LOG, 'log').map(toLogEntry), {
    keysOf,
  });
  if (!result.ok) throw new Error(result.reason);
  return result.state;
}

/** A leaf proof of a vector. */
function toLeafProof(json: Json, size: number): LeafProof {
  return {
    index: num(json, 'index'),
    size,
    leaf: toLeaf(child(json, 'leaf')),
    path: (json['path'] as string[]).map(fromHex),
  };
}

/** What each checkpoint a case is judged by holds, from its proofs verified against the log. */
function checkpointLeavesOf(
  json: Json,
  write: SectionWrite,
  log: VaultLogState,
): Map<number, CheckpointLeaf | undefined> {
  const held = new Map<number, CheckpointLeaf | undefined>();
  for (const proof of objects(json, 'checkpointProofs')) {
    const seq = num(proof, 'checkpointSeq');
    const size = num(proof, 'size');
    const checkpoint = log.checkpoints.find((record) => record.seq === seq);
    if (checkpoint === undefined) throw new Error('checkpoint');
    const optional = (key: string): LeafProof | undefined =>
      proof[key] === undefined ? undefined : toLeafProof(child(proof, key), size);
    const lookup = resolveCheckpointProof(
      {
        size,
        inclusion: optional('inclusion'),
        before: optional('before'),
        after: optional('after'),
      },
      write,
      checkpoint.root,
    );
    if (!lookup.verified) throw new Error(`proof ${String(seq)} does not hold`);
    held.set(seq, lookup.leaf);
  }
  return held;
}

/** Judges a write as a reader does: its standing, then its content. */
function judge(
  write: SectionWrite,
  log: VaultLogState,
  checkpointLeaves: ReadonlyMap<number, CheckpointLeaf | undefined>,
  vaultKey = vaultKeyOf(write.vaultKeyVersion),
): { readonly reason: WriteRefusal | null; readonly content?: Uint8Array | undefined } {
  const header = { ...toSectionHeader(write), signature: write.signature };
  const standing = verifySectionStanding(header, log, { keysOf, checkpointLeaves });
  if (!standing.ok) return { reason: standing.reason };
  const content = openSectionContent(write, log, vaultKey, header.ciphertextHash);
  return content.ok ? { reason: null, content: content.content } : { reason: content.reason };
}

/** A named case. */
function sectionCase(name: string): Json {
  const found = CASES.find((json) => text(json, 'name') === name);
  if (found === undefined) throw new Error(name);
  return found;
}

describe('section writes', () => {
  const log = scenarioLog();

  it.each(CASES.map((json) => [text(json, 'name'), json] as const))(
    'gives the vector verdict for %s',
    (_, json) => {
      const write = toSectionWrite(json);
      const header = toSectionHeader(write);
      expect(toHex(sectionWriteMessage(write))).toBe(text(json, 'message'));
      expect(toHex(sectionHeaderMessage(header))).toBe(text(json, 'message'));
      expect(toHex(writeHash(write))).toBe(text(json, 'writeHash'));
      expect(toHex(headerWriteHash(header))).toBe(text(json, 'writeHash'));
      expect(toHex(header.ciphertextHash ?? new Uint8Array(32))).toBe(
        text(child(json, 'write'), 'ciphertextHash'),
      );

      const result = judge(write, log, checkpointLeavesOf(json, write, log));
      expect(result.reason).toBe(json['reason']);
      if (result.reason === null && json['contentUtf8'] !== undefined) {
        expect(new TextDecoder().decode(result.content)).toBe(text(json, 'contentUtf8'));
      }
    },
  );

  it('judges each case by the first and the latest checkpoint after its head', () => {
    for (const json of CASES) {
      const write = toSectionWrite(json);
      const { first, latest } = checkpointsAfter(log, write.logSeq);
      const expected = [...new Set([first?.seq, latest?.seq])].filter(
        (seq): seq is number => seq !== undefined,
      );
      expect(objects(json, 'checkpointProofs').map((proof) => num(proof, 'checkpointSeq'))).toEqual(
        expected,
      );
    }
  });

  it('refuses a write whose checkpoints were not looked up', () => {
    const write = toSectionWrite(sectionCase('bob-secrets-1'));
    const header = { ...toSectionHeader(write), signature: write.signature };
    expect(() =>
      verifySectionStanding(header, log, { keysOf, checkpointLeaves: new Map() }),
    ).toThrow(RangeError);
  });

  it('refuses a write that should stand when a checkpoint does not hold it', () => {
    const json = sectionCase('bob-secrets-1');
    const write = toSectionWrite(json);
    const absent = new Map(
      [...checkpointLeavesOf(json, write, log).keys()].map((seq) => [seq, undefined] as const),
    );
    expect(judge(write, log, absent).reason).toBe('not_in_checkpoint');
  });

  it('refuses a write the latest checkpoint shows superseded or forked', () => {
    const json = sectionCase('bob-secrets-1');
    const write = toSectionWrite(json);
    const held = checkpointLeavesOf(json, write, log);
    const { first, latest } = checkpointsAfter(log, write.logSeq);
    const latestSeq = latest?.seq ?? 0;
    // The first checkpoint holds this very write; the latest is made to hold it too, then not.
    const leaf = held.get(first?.seq ?? 0);
    if (leaf === undefined || latestSeq === first?.seq) throw new Error('leaf');
    expect(judge(write, log, new Map(held).set(latestSeq, leaf)).reason).toBeNull();
    const newer = new Map(held).set(latestSeq, { ...leaf, dataVersion: leaf.dataVersion + 1 });
    expect(judge(write, log, newer).reason).toBe('rollback');
    const forked = new Map(held).set(latestSeq, { ...leaf, writeHash: new Uint8Array(32) });
    expect(judge(write, log, forked).reason).toBe('fork');
  });

  it('judges standing from the header alone and refuses content that does not match it', () => {
    const json = sectionCase('owner-secrets-2');
    const write = toSectionWrite(json);
    const header = { ...toSectionHeader(write), signature: write.signature };
    const checkpointLeaves = checkpointLeavesOf(json, write, log);
    expect(verifySectionStanding(header, log, { keysOf, checkpointLeaves }).ok).toBe(true);
    const swapped = { ...write, ciphertext: write.ciphertext?.slice().fill(7) };
    expect(
      openSectionContent(swapped, log, vaultKeyOf(write.vaultKeyVersion), header.ciphertextHash),
    ).toEqual({ ok: false, reason: 'bad_ciphertext' });
    expect(openSectionContent(write, log, vaultKeyOf(1), header.ciphertextHash).ok).toBe(
      write.vaultKeyVersion === 1,
    );
  });

  it('skips only the signature of a header the reader verified before', () => {
    const json = sectionCase('owner-secrets-2');
    const write = toSectionWrite(json);
    const checkpointLeaves = checkpointLeavesOf(json, write, log);
    const forged = { ...toSectionHeader(write), signature: new Uint8Array(65) };
    expect(verifySectionStanding(forged, log, { keysOf, checkpointLeaves }).ok).toBe(false);
    expect(
      verifySectionStanding(forged, log, { keysOf, checkpointLeaves, signatureVerified: true }).ok,
    ).toBe(true);
    const elsewhere = { ...forged, logSeq: 3 };
    expect(
      verifySectionStanding(elsewhere, log, { keysOf, checkpointLeaves, signatureVerified: true })
        .ok,
    ).toBe(false);
  });

  it('refuses every write of a vault once its log ends in vault_deleted', () => {
    const after = child(SECTIONS, 'afterDeletion');
    const deleted = replayVaultLog(
      text(LOG, 'vaultId'),
      [toLogEntry(child(after, 'entry'))],
      { keysOf },
      log,
    );
    if (!deleted.ok) throw new Error(deleted.reason);
    expect(deleted.state.deleted).toBe(true);
    expect(deleted.state.points.at(-1)?.head).toBe(false);
    const json = sectionCase(text(after, 'write'));
    const write = toSectionWrite(json);
    expect(judge(write, log, checkpointLeavesOf(json, write, log)).reason).toBeNull();
    expect(judge(write, deleted.state, checkpointLeavesOf(json, write, log)).reason).toBe(
      text(after, 'reason'),
    );
  });

  it('refuses content under a vault key that is not the committed one', () => {
    const json = sectionCase('owner-secrets-2');
    const write = toSectionWrite(json);
    expect(judge(write, log, checkpointLeavesOf(json, write, log), new Uint8Array(32))).toEqual({
      reason: 'key_mismatch',
    });
  });

  it('signs and encrypts writes as the vectors do', () => {
    const json = sectionCase('owner-secrets-2');
    const write = toSectionWrite(json);
    const owner = IDENTITIES.find(
      (identity) =>
        identity.keys.userId === write.writerUserId &&
        identity.keys.keyVersion === write.writerKeyVersion,
    );
    if (owner === undefined || write.ciphertext === undefined) throw new Error('fixture');
    expect(toHex(signSectionWrite(write, owner.signingSeed))).toBe(text(json, 'signature'));
    const vaultKey = vaultKeyOf(write.vaultKeyVersion);
    if (vaultKey === undefined) throw new Error('vault key');
    // Re-encrypting with the vector's own nonce gives back the same ciphertext.
    const nonce = write.ciphertext.slice(1, 25);
    expect(toHex(encryptSection(vaultKey, write, utf8Of(text(json, 'contentUtf8')), nonce))).toBe(
      toHex(write.ciphertext),
    );
    expect(() => {
      requireSectionSize(write.ciphertext ?? new Uint8Array());
    }).not.toThrow();
    expect(() => {
      requireSectionSize(new Uint8Array(41 + 255));
    }).toThrow();
  });
});

describe('section marks', () => {
  it.each(objects(SECTIONS, 'marks').map((json) => [text(json, 'name'), json] as const))(
    'refuses %s',
    (_, json) => {
      const seen = toSectionWrite(sectionCase(text(json, 'seen')));
      const then = toSectionWrite(sectionCase(text(json, 'then')));
      const mark = { dataVersion: seen.dataVersion, writeHash: writeHash(seen) };
      expect(checkSectionOrder(mark, { ...then, writeHash: writeHash(then) })).toBe(
        text(json, 'reason'),
      );
    },
  );

  it('accepts the same write and the next one, and refuses rollbacks and unchained writes', () => {
    const first = toSectionWrite(sectionCase('bob-general-2'));
    const next = toSectionWrite(sectionCase('owner-general-3'));
    const mark = { dataVersion: first.dataVersion, writeHash: writeHash(first) };
    const nextMark = { dataVersion: next.dataVersion, writeHash: writeHash(next) };

    expect(checkSectionOrder(undefined, { ...first, writeHash: writeHash(first) })).toBeUndefined();
    expect(checkSectionOrder(mark, { ...first, writeHash: writeHash(first) })).toBeUndefined();
    expect(checkSectionOrder(mark, { ...next, writeHash: writeHash(next) })).toBeUndefined();
    expect(checkSectionOrder(nextMark, { ...first, writeHash: writeHash(first) })).toBe('rollback');
    expect(
      checkSectionOrder(mark, {
        ...next,
        previousWriteHash: undefined,
        writeHash: writeHash(next),
      }),
    ).toBe('fork');
  });
});
