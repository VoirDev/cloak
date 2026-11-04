import {
  randomBytes,
  type Membership,
  type MembershipChange,
  type VaultLogState,
} from '@voirdev/cloak-crypto';
import { describe, expect, it } from 'vitest';

import { createMemoryStorage, type CloakStorage } from '../src/storage/CloakStorage.ts';
import { openLocalState } from '../src/storage/localState.ts';

const USER = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e';
/** Another user whose id differs from {@link USER} only in its last character. */
const OTHER_USER = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0f';
const SECTION = {
  vaultId: '0192f5a3-0000-7aaa-8bbb-0123456789ab',
  nodeId: '0192f5a5-1111-7aaa-8bbb-0123456789ab',
  sectionName: 'general',
};

/** A store whose records the test can read and rewrite, like a hostile storage layer. */
function inspectableStorage(): CloakStorage & { readonly records: Map<string, Uint8Array> } {
  const records = new Map<string, Uint8Array>();
  return {
    records,
    get: (key) => Promise.resolve(records.get(key)),
    set: (key, value) => {
      records.set(key, value);
      return Promise.resolve();
    },
    delete: (key) => {
      records.delete(key);
      return Promise.resolve();
    },
    deletePrefix: (prefix) => {
      for (const key of [...records.keys()]) if (key.startsWith(prefix)) records.delete(key);
      return Promise.resolve();
    },
  };
}

describe('local state', () => {
  it('keeps pins, heads, marks and own writes across sessions with the same key', async () => {
    const storage = createMemoryStorage();
    const key = randomBytes(32);
    const first = openLocalState(storage, USER, key);
    await first.setPin('bob', { keyVersion: 1, keysDigest: new Uint8Array(32).fill(7) });
    await first.advanceHead('vault', { seq: 4, entryHash: new Uint8Array(32).fill(1) });
    await first.raiseMark(SECTION, { dataVersion: 3, writeHash: new Uint8Array(32).fill(2) });
    await first.setOwnWrite(SECTION, new Uint8Array(32).fill(3));

    const second = openLocalState(storage, USER, key);
    expect(await second.pin('bob')).toEqual({
      keyVersion: 1,
      keysDigest: new Uint8Array(32).fill(7),
    });
    expect((await second.head('vault'))?.seq).toBe(4);
    expect((await second.mark(SECTION))?.dataVersion).toBe(3);
    expect(await second.ownWrite(SECTION)).toEqual(new Uint8Array(32).fill(3));
  });

  it('never lowers a head or a mark', async () => {
    const state = openLocalState(createMemoryStorage(), USER, randomBytes(32));
    await state.advanceHead('vault', { seq: 5, entryHash: new Uint8Array(32).fill(5) });
    await state.advanceHead('vault', { seq: 3, entryHash: new Uint8Array(32).fill(3) });
    await state.raiseMark(SECTION, { dataVersion: 7, writeHash: new Uint8Array(32).fill(7) });
    await state.raiseMark(SECTION, { dataVersion: 2, writeHash: new Uint8Array(32).fill(2) });

    expect((await state.head('vault'))?.seq).toBe(5);
    expect((await state.mark(SECTION))?.dataVersion).toBe(7);
  });

  it('refuses a record that was changed or moved to another name', async () => {
    const storage = inspectableStorage();
    const state = openLocalState(storage, USER, randomBytes(32));
    await state.advanceHead('a', { seq: 1, entryHash: new Uint8Array(32) });
    await state.advanceHead('b', { seq: 9, entryHash: new Uint8Array(32) });
    const [nameA, recordA] =
      [...storage.records].find(([name]) => name.endsWith('/vaults/a/head')) ?? [];
    const [nameB] = [...storage.records].find(([name]) => name.endsWith('/vaults/b/head')) ?? [];
    if (nameA === undefined || recordA === undefined || nameB === undefined)
      throw new Error('records');

    storage.records.set(nameB, recordA);
    await expect(state.head('b')).rejects.toMatchObject({ code: 'decryption_failed' });
    const tampered = recordA.slice();
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
    storage.records.set(nameA, tampered);
    await expect(state.head('a')).rejects.toMatchObject({ code: 'decryption_failed' });
  });

  it('forgets a vault but keeps its head when a signed fact ended the membership', async () => {
    const storage = inspectableStorage();
    const state = openLocalState(storage, USER, randomBytes(32));
    const other = { ...SECTION, vaultId: `${SECTION.vaultId.slice(0, -1)}0` };
    for (const section of [SECTION, other]) {
      await state.advanceHead(section.vaultId, { seq: 4, entryHash: new Uint8Array(32).fill(4) });
      await state.raiseSnapshot(section.vaultId, snapshotOf(2));
      await state.raiseMark(section, { dataVersion: 3, writeHash: new Uint8Array(32).fill(3) });
      await state.setOwnWrite(section, new Uint8Array(32).fill(1));
      await state.addOwnEntries(section.vaultId, [new Uint8Array(32).fill(2)]);
    }

    await state.forgetVault(SECTION.vaultId, true);

    expect((await state.head(SECTION.vaultId))?.seq).toBe(4);
    expect(await state.snapshot(SECTION.vaultId)).toBeUndefined();
    expect(await state.mark(SECTION)).toBeUndefined();
    expect(await state.ownWrite(SECTION)).toBeUndefined();
    expect(await state.ownEntries(SECTION.vaultId)).toEqual([]);
    // The other vault, whose id shares all but its last character, is untouched.
    expect((await state.mark(other))?.dataVersion).toBe(3);
    expect(await state.ownEntries(other.vaultId)).toHaveLength(1);

    await state.forgetVault(SECTION.vaultId, false);
    expect(await state.head(SECTION.vaultId)).toBeUndefined();
    expect((await state.head(other.vaultId))?.seq).toBe(4);
  });

  it('clears every record of the user and none of another user', async () => {
    const storage = inspectableStorage();
    const mine = openLocalState(storage, USER, randomBytes(32));
    const theirs = openLocalState(storage, OTHER_USER, randomBytes(32));
    await mine.setPin('bob', { keyVersion: 1, keysDigest: new Uint8Array(32) });
    await mine.setHostId('bob', 'bob@example.com');
    await mine.advanceHead('vault', { seq: 1, entryHash: new Uint8Array(32) });
    await theirs.setPin('bob', { keyVersion: 1, keysDigest: new Uint8Array(32) });

    await mine.clear();

    expect(
      [...storage.records.keys()].every((name) => name.startsWith(`cloak/v1/${OTHER_USER}/`)),
    ).toBe(true);
    expect(await theirs.pin('bob')).toBeDefined();
  });

  it('keeps the host user ids it was given', async () => {
    const storage = createMemoryStorage();
    const key = randomBytes(32);
    await openLocalState(storage, USER, key).setHostId('bob', 'bob@example.com');

    expect(await openLocalState(storage, USER, key).hostId('bob')).toBe('bob@example.com');
    expect(await openLocalState(storage, USER, key).hostId('carol')).toBeUndefined();
  });

  it('moves records sealed under the previous local state key to the new one', async () => {
    const storage = inspectableStorage();
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    await openLocalState(storage, USER, oldKey).setPin('bob', {
      keyVersion: 2,
      keysDigest: new Uint8Array(32).fill(9),
    });

    const migrated = openLocalState(storage, USER, newKey, oldKey);
    expect((await migrated.pin('bob'))?.keyVersion).toBe(2);

    // Sealed again under the new key: it now opens without the previous one.
    expect((await openLocalState(storage, USER, newKey).pin('bob'))?.keyVersion).toBe(2);
    await expect(openLocalState(storage, USER, oldKey).pin('bob')).rejects.toMatchObject({
      code: 'decryption_failed',
    });
  });

  it('keeps a vault snapshot whole, and never lowers it to a shorter one', async () => {
    const local = openLocalState(createMemoryStorage(), USER, randomBytes(32));
    const long = snapshotOf(5);
    await local.raiseSnapshot(SECTION.vaultId, long);
    expect(await local.snapshot(SECTION.vaultId)).toEqual(long);

    await local.raiseSnapshot(SECTION.vaultId, snapshotOf(3));
    expect((await local.snapshot(SECTION.vaultId))?.points).toHaveLength(5);
    await local.raiseSnapshot(SECTION.vaultId, snapshotOf(7));
    expect((await local.snapshot(SECTION.vaultId))?.points).toHaveLength(7);

    // A snapshot is bound to its vault: one stored under another name does not open as it.
    expect(await local.snapshot('0192f5a3-0000-7aaa-8bbb-0123456789ac')).toBeUndefined();
  });
});

/** A verified state of [length] entries: the owner created the vault, then added and removed Bob. */
function snapshotOf(length: number): VaultLogState {
  const owner: Membership = {
    role: 'owner',
    keyVersion: 1,
    keysDigest: new Uint8Array(32).fill(4),
  };
  const bob: Membership = { role: 'editor', keyVersion: 2, keysDigest: new Uint8Array(32).fill(5) };
  const bobHistory: MembershipChange[] = [{ seq: 2, membership: bob }];
  if (length >= 3) bobHistory.push({ seq: 3, membership: undefined });
  return {
    vaultId: SECTION.vaultId,
    points: Array.from({ length }, (_, index) => ({
      seq: index + 1,
      hash: new Uint8Array(32).fill(index + 1),
      head: true,
      keyVersion: index >= 3 ? 2 : 1,
      authorUserId: USER,
      authorKeyVersion: 1,
    })),
    members: new Map(
      length >= 3
        ? [[USER, owner]]
        : [
            [USER, owner],
            ['bob', bob],
          ],
    ),
    history: new Map([
      [USER, [{ seq: 1, membership: owner }]],
      ['bob', bobHistory],
    ]),
    checkpoints: length >= 3 ? [{ seq: 3, root: new Uint8Array(32).fill(6) }] : [],
    commitments: new Map(
      length >= 4
        ? [
            [1, new Uint8Array(32).fill(7)],
            [2, new Uint8Array(32).fill(8)],
          ]
        : [[1, new Uint8Array(32).fill(7)]],
    ),
    recordedKeyVersions: new Map([['bob', 2]]),
    sinceRotation: { departed: length >= 3 ? ['bob'] : [], replacedKeys: [] },
    nodes: new Map([['node', { ownerUserId: USER, nodeKey: 'record-1', seq: 2 }]]),
    shares: new Map([
      [
        'shared',
        {
          ownerUserId: USER,
          homeVaultId: 'home',
          nodeKey: 'record-2',
          all: undefined,
          names: new Map([['notes', 2]]),
        },
      ],
    ]),
    deleted: false,
    placesChangedAt: 2,
  };
}
