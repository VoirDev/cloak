import { describe, expect, it } from 'vitest';

import {
  KIND_CODE,
  ROLE_CODE,
  entryHash,
  keysDigest,
  logHead,
  logMessage,
  membershipAt,
  replayVaultLog,
  signLogEntry,
  type LogEntry,
  type LogEntryFields,
  type ReplayResult,
} from '../src/index.ts';
import { BadFlag, IDENTITIES, keysOf, toLogEntry } from './fixtures.ts';
import { child, num, objects, text, toHex, vectors, type Json } from './vectors.ts';

const LOG = vectors('vault-log.json');
const VAULT = text(LOG, 'vaultId');
const ENTRIES = objects(LOG, 'log');
const OWNER = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e';
const BOB = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d1f';

/** Replays a vector log, mapping an undecodable flag to the refusal decoding gives. */
function replay(log: readonly Json[]): ReplayResult {
  const entries: LogEntry[] = [];
  for (const json of log) {
    try {
      entries.push(toLogEntry(json));
    } catch (error: unknown) {
      if (error instanceof BadFlag)
        return { ok: false, reason: 'bad_flag', failSeq: entries.length + 1 };
      throw error;
    }
  }
  return replayVaultLog(VAULT, entries, { keysOf });
}

describe('vault log', () => {
  it('uses the protocol enumerations', () => {
    const enumerations = child(LOG, 'enumerations');
    expect(child(enumerations, 'role')).toEqual(ROLE_CODE);
    expect(child(enumerations, 'kind')).toEqual(KIND_CODE);
  });

  it('builds, hashes and signs every entry of the scenario', () => {
    for (const json of ENTRIES) {
      const entry = toLogEntry(json);
      expect(toHex(logMessage(entry))).toBe(text(json, 'message'));
      expect(toHex(entryHash(entry))).toBe(text(json, 'entryHash'));
      const author = IDENTITIES.find(
        (identity) =>
          identity.keys.userId === entry.authorUserId &&
          identity.keys.keyVersion === entry.authorKeyVersion,
      );
      if (author === undefined) throw new Error('author');
      expect(toHex(signLogEntry(entry, author.signingSeed))).toBe(text(json, 'signature'));
    }
  });

  it('accepts the scenario log and tracks members, keys and checkpoints', () => {
    const result = replay(ENTRIES);
    if (!result.ok) throw new Error(`${result.reason} at ${String(result.failSeq)}`);
    const { state } = result;

    expect(logHead(state).seq).toBe(ENTRIES.length);
    expect(logHead(state).keyVersion).toBe(3);
    expect([...state.members.keys()]).toEqual([OWNER]);
    expect(state.members.get(OWNER)?.keyVersion).toBe(2);
    expect(state.checkpoints.map((checkpoint) => checkpoint.seq)).toEqual([5, 7, 8, 10]);
    expect(state.points.map((point) => point.head)).toEqual([
      true,
      true,
      true,
      true,
      true,
      false,
      true,
      true,
      true,
      true,
      true,
      true,
    ]);
    expect([...state.commitments.keys()]).toEqual([1, 2, 3]);
    expect(state.deleted).toBe(false);
    expect([...state.nodes.keys()]).toHaveLength(1);
    expect([...state.shares.keys()]).toHaveLength(1);
    expect(membershipAt(state, BOB, 4)?.role).toBe('editor');
    expect(membershipAt(state, BOB, 5)?.role).toBe('viewer');
    expect(membershipAt(state, BOB, ENTRIES.length)).toBeUndefined();
    expect(membershipAt(state, BOB, 0)).toBeUndefined();
    expect(state.recordedKeyVersions.get(OWNER)).toBe(2);
    expect(state.points.map((point) => point.authorUserId)).toEqual(
      ENTRIES.map((json) => text(child(json, 'entry'), 'authorUserId')),
    );
  });

  it('tells who exposed the current key since the last rotation', () => {
    const before = replay(ENTRIES.slice(0, 7));
    const exposed = replay(ENTRIES.slice(0, 9));
    const full = replay(ENTRIES);
    if (!before.ok || !exposed.ok || !full.ok) throw new Error('replay');
    expect(before.state.sinceRotation).toEqual({ departed: [], replacedKeys: [] });
    expect(exposed.state.sinceRotation.replacedKeys).toEqual([OWNER]);
    expect(exposed.state.sinceRotation.departed).toEqual([BOB]);
    // The renewal at the end rotates the key again, so nobody outside knows it.
    expect(full.state.sinceRotation).toEqual({ departed: [], replacedKeys: [] });
  });

  it('keeps one history change per membership change, however many members a request touches', () => {
    const owner = IDENTITIES.find(
      (identity) => identity.keys.userId === OWNER && identity.keys.keyVersion === 1,
    );
    if (owner === undefined) throw new Error('owner');
    const people = Array.from({ length: 300 }, (_, index) => ({
      userId: `0192f5a6-0000-7000-8000-${String(index).padStart(12, '0')}`,
      keyVersion: 1,
      cryptoSuite: 1,
      encryptionPublicKey: new Uint8Array(32).fill(1),
      signingPublicKey: new Uint8Array(32).fill(2),
      recoverySigningPublicKey: new Uint8Array(32).fill(3),
    }));
    const peopleKeys = new Map(people.map((keys) => [keys.userId, keys]));
    const keysOfAll = (userId: string, keyVersion: number) =>
      peopleKeys.get(userId) ?? keysOf(userId, keyVersion);
    const created = toLogEntry(ENTRIES[0] ?? {});
    const entries: LogEntry[] = [created];
    let previousHash = entryHash(created);
    const append = (fields: Omit<LogEntryFields, 'vaultId' | 'seq' | 'previousHash'>) => {
      const entryFields: LogEntryFields = {
        ...fields,
        vaultId: VAULT,
        seq: entries.length + 1,
        previousHash,
      };
      entries.push({ ...entryFields, signature: signLogEntry(entryFields, owner.signingSeed) });
      previousHash = entryHash(entryFields);
    };
    for (const keys of people) {
      append({
        kind: 'member_added',
        subjectUserId: keys.userId,
        role: 'editor',
        keyVersion: 1,
        subjectKeys: keysDigest(keys),
        subjectKeyVersion: 1,
        requestEnd: true,
        authorUserId: OWNER,
        authorKeyVersion: 1,
      });
    }
    // One rotation request removes everyone.
    people.forEach((keys) => {
      append({
        kind: 'member_removed',
        subjectUserId: keys.userId,
        keyVersion: 1,
        subjectKeys: keysDigest(keys),
        subjectKeyVersion: 1,
        requestEnd: false,
        authorUserId: OWNER,
        authorKeyVersion: 1,
      });
    });
    append({
      kind: 'key_rotated',
      keyVersion: 2,
      keyCommitment: new Uint8Array(32).fill(9),
      checkpoint: new Uint8Array(32).fill(8),
      requestEnd: true,
      authorUserId: OWNER,
      authorKeyVersion: 1,
    });

    const result = replayVaultLog(VAULT, entries, { keysOf: keysOfAll });
    if (!result.ok) throw new Error(`${result.reason} at ${String(result.failSeq)}`);
    const { state } = result;
    expect(state.points).toHaveLength(entries.length);
    expect([...state.members.keys()]).toEqual([OWNER]);
    const changes = [...state.history.values()].reduce((sum, list) => sum + list.length, 0);
    expect(changes).toBe(1 + 2 * people.length);
    const someone = people[150]?.userId ?? '';
    expect(membershipAt(state, someone, 1 + 151)?.role).toBe('editor');
    expect(membershipAt(state, someone, entries.length)).toBeUndefined();

    // Continuing a snapshot does not change the snapshot it continues.
    const prefix = replayVaultLog(VAULT, entries.slice(0, 301), { keysOf: keysOfAll });
    if (!prefix.ok) throw new Error('prefix');
    const historyBefore = prefix.state.history.get(someone)?.length;
    const rest = replayVaultLog(VAULT, entries.slice(301), { keysOf: keysOfAll }, prefix.state);
    expect(rest).toEqual(result);
    expect(prefix.state.history.get(someone)?.length).toBe(historyBefore);
    expect(prefix.state.members.size).toBe(301);
  });

  it('continues a verified snapshot with new entries', () => {
    const full = replay(ENTRIES);
    const prefix = replay(ENTRIES.slice(0, 4));
    if (!full.ok || !prefix.ok) throw new Error('replay');

    const rest = replayVaultLog(VAULT, ENTRIES.slice(4).map(toLogEntry), { keysOf }, prefix.state);
    expect(rest).toEqual(full);

    const gap = replayVaultLog(VAULT, ENTRIES.slice(5).map(toLogEntry), { keysOf }, prefix.state);
    expect(gap).toEqual({ ok: false, reason: 'broken_chain', failSeq: 5 });
  });

  it('refuses entries of another vault and an empty log', () => {
    const entries = ENTRIES.map(toLogEntry);
    expect(replayVaultLog('0192f5a3-0000-7aaa-8bbb-0123456789ac', entries, { keysOf })).toEqual({
      ok: false,
      reason: 'broken_chain',
      failSeq: 1,
    });
    expect(replayVaultLog(VAULT, [], { keysOf })).toEqual({
      ok: false,
      reason: 'broken_chain',
      failSeq: 1,
    });
  });

  it('refuses an author whose key version the reader knows was superseded', () => {
    const entries = ENTRIES.map(toLogEntry);
    const result = replayVaultLog(VAULT, entries, {
      keysOf,
      isSuperseded: (userId, keyVersion) =>
        userId === '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e' && keyVersion === 1,
    });
    expect(result).toEqual({ ok: false, reason: 'superseded_keys', failSeq: 1 });
  });

  it.each(objects(LOG, 'negatives').map((json) => [text(json, 'name'), json] as const))(
    'refuses %s',
    (_, json) => {
      expect(replay(objects(json, 'log'))).toEqual({
        ok: false,
        reason: text(json, 'reason'),
        failSeq: num(json, 'failSeq'),
      });
    },
  );
});
