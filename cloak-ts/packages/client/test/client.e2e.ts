import { cloakUserId } from '@voirdev/cloak-crypto';
import { describe, expect, inject, it } from 'vitest';

import {
  CloakFingerprintRequiredError,
  CloakSessionClosedError,
  CloakKeyUnavailableError,
  CloakSecretKeyMissingError,
  createCloakClient,
  createMemoryStorage,
  isCloakApiError,
  nodeIdFor,
  type CloakClient,
  type CloakSession,
  type CloakStorage,
  type DecryptedSection,
} from '../src/index.ts';

/**
 * A client of one host user; the dev host trusts this header as its session. [fail] makes chosen
 * requests fail as if the connection dropped.
 */
function clientFor(
  userId: string,
  storage: CloakStorage = createMemoryStorage(),
  fail?: (request: Request) => boolean,
): CloakClient {
  return createCloakClient({
    baseUrl: inject('cloakBaseUrl'),
    storage,
    headers: () => ({ 'X-Cloak-Dev-User': userId }),
    ...(fail === undefined
      ? {}
      : {
          fetch: (input: RequestInfo | URL, init?: RequestInit) => {
            const request = new Request(input, init);
            return fail(request) ? Promise.reject(new TypeError('Network error')) : fetch(request);
          },
        }),
  });
}

/** A registered user with their client, session and codes. */
interface User {
  readonly userId: string;
  readonly client: CloakClient;
  readonly session: CloakSession;
  readonly secretKeyCode: string;
  readonly recoveryKeyCode: string;
}

/** Registers a fresh user. */
async function user(password = 'correct horse', storage?: CloakStorage): Promise<User> {
  const userId = crypto.randomUUID();
  const client = clientFor(userId, storage);
  const registered = await client.register({ userId, password });
  return { userId, client, ...registered };
}

/** Lets [admin] add [member]: confirms their fingerprint as if compared in person, and [member] accepts [admin]'s vaults. */
async function meet(admin: User, member: User): Promise<void> {
  await admin.session.confirmFingerprint(member.userId, member.session.fingerprint);
  // People who know each other accept what the other adds them to.
  await member.session.acceptInvitationsFrom(admin.userId);
}

/** The content of a section that must have verified. */
function contentOf(section: DecryptedSection): unknown {
  if (section.status !== 'ok')
    throw new Error(
      `Expected content, got ${section.status === 'refused' ? section.reason : 'a deletion'}`,
    );
  return section.content;
}

/** Erases a user as the host would, through the development host's test-only hook. */
async function erase(hostUserId: string): Promise<void> {
  const origin = new URL(inject('cloakBaseUrl')).origin;
  const response = await fetch(`${origin}/dev/users/${encodeURIComponent(hostUserId)}/erase`, {
    method: 'POST',
  });
  if (response.status !== 204) throw new Error(`Erase answered ${String(response.status)}`);
}

/** A memory store that also tells which record keys it holds. */
function listedStorage(): { readonly storage: CloakStorage; readonly keys: () => string[] } {
  const inner = createMemoryStorage();
  const held = new Set<string>();
  return {
    keys: () => [...held],
    storage: {
      get: (key) => inner.get(key),
      set: async (key, value) => {
        held.add(key);
        await inner.set(key, value);
      },
      delete: async (key) => {
        held.delete(key);
        await inner.delete(key);
      },
      deletePrefix: async (prefix) => {
        for (const key of [...held]) if (key.startsWith(prefix)) held.delete(key);
        await inner.deletePrefix(prefix);
      },
    },
  };
}

/** Expects a promise to fail with a Cloak API error code. */
async function expectApiError(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => isCloakApiError(error, code));
}

describe('the TypeScript client against the Kotlin server', () => {
  it('registers, unlocks only with the right secrets, changes the password and recovers', async () => {
    const storage = createMemoryStorage();
    const alice = await user('pässword', storage);

    const unlocked = await alice.client.unlock({
      password: 'pässword',
      secretKeyCode: alice.secretKeyCode,
      rememberSecretKey: true,
    });
    expect(unlocked.fingerprint).toBe(alice.session.fingerprint);
    await expect(alice.client.unlock({ password: 'wrong' })).rejects.toMatchObject({
      name: 'CloakUnlockError',
      reason: 'wrong_credentials',
    });
    await expect(
      alice.client.recover({ recoveryKeyCode: (await user()).recoveryKeyCode, newPassword: 'x' }),
    ).rejects.toMatchObject({ name: 'CloakUnlockError', reason: 'wrong_recovery_key' });

    await alice.client.changePassword({ password: 'pässword', newPassword: 'new one' });
    await alice.client.unlock({ password: 'new one' });

    const recovered = await alice.client.recover({
      recoveryKeyCode: alice.recoveryKeyCode,
      newPassword: 'third',
    });
    await expect(alice.client.unlock({ password: 'third' })).rejects.toBeInstanceOf(
      CloakSecretKeyMissingError,
    );
    const again = await alice.client.unlock({
      password: 'third',
      secretKeyCode: recovered.secretKeyCode,
    });
    expect(again.fingerprint).toBe(alice.session.fingerprint);
  });

  it('members read and write what their role allows, and every reader verifies', async () => {
    const alice = await user();
    const bob = await user();
    const carol = await user();
    const vault = await alice.session.createVault();

    await expect(alice.session.addMember(vault.id, bob.userId, 'editor')).rejects.toBeInstanceOf(
      CloakFingerprintRequiredError,
    );
    await meet(alice, bob);
    await meet(alice, carol);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const opened = await alice.session.addMember(vault.id, carol.userId, 'viewer');
    expect(opened.members.map((member) => member.role).sort()).toEqual([
      'editor',
      'owner',
      'viewer',
    ]);

    const node = await bob.session.createNode(vault.id, 'db-1');
    await bob.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: { name: 'db-1' },
    });
    expect(
      contentOf(await carol.session.readSection(vault.id, nodeIdFor(node), 'general')),
    ).toEqual({
      name: 'db-1',
    });
    await expectApiError(
      carol.session.writeSection(vault.id, node, 'general', { type: 'server', content: {} }),
      'role_required',
    );

    // Bob loses the right to write; what he wrote before stays valid through the checkpoint.
    await alice.session.setRole(vault.id, bob.userId, 'viewer');
    expect(
      contentOf(await carol.session.readSection(vault.id, nodeIdFor(node), 'general')),
    ).toEqual({
      name: 'db-1',
    });
    await expectApiError(
      bob.session.writeSection(vault.id, node, 'general', { type: 'server', content: {} }),
      'role_required',
    );

    // Carol is removed with a rotation and reads nothing after it; Bob still reads new content.
    const rotated = await alice.session.rotate(vault.id, [carol.userId]);
    expect(rotated.keyVersion).toBe(2);
    await alice.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: { name: 'db-2' },
    });
    expect(contentOf(await bob.session.readSection(vault.id, nodeIdFor(node), 'general'))).toEqual({
      name: 'db-2',
    });
    await expectApiError(
      carol.session.readSection(vault.id, nodeIdFor(node), 'general'),
      'not_found',
    );
  });

  it('nodes span vaults, sections move between them, and the change feed shows only news', async () => {
    const alice = await user();
    const bob = await user();
    const team = await alice.session.createVault();
    const client = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(client.id, bob.userId, 'viewer');

    const node = await alice.session.createNode(team.id, 'record');
    await alice.session.shareNode(node, client.id, ['general', 'secrets']);
    await alice.session.writeSections([
      {
        vaultId: team.id,
        node,
        name: 'secrets',
        type: 'server',
        content: { password: 'hunter2' },
      },
      {
        vaultId: client.id,
        node,
        name: 'general',
        type: 'server',
        content: { ip: '10.0.0.5' },
      },
    ]);
    expect((await alice.session.readNode(nodeIdFor(node))).sections).toHaveLength(2);
    expect(
      (await bob.session.readNode(nodeIdFor(node))).sections.map((section) => section.name),
    ).toEqual(['general']);

    const { lastChangeSeq } = await bob.session.changes(client.id);
    await alice.session.moveSection(node, 'secrets', team.id, client.id);
    const news = await bob.session.changes(client.id, lastChangeSeq);
    expect(news.sections.map((section) => [section.name, contentOf(section)])).toEqual([
      ['secrets', { password: 'hunter2' }],
    ]);
    expect((await alice.session.readSection(team.id, nodeIdFor(node), 'secrets')).status).toBe(
      'deleted',
    );
  });

  it('an editor leaves with a checkpoint, and admins see that a rotation is due', async () => {
    const alice = await user();
    const bob = await user();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const node = await bob.session.createNode(vault.id, 'record');
    await bob.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: { by: 'bob' },
    });

    await bob.session.leave(vault.id);

    const view = await alice.session.openVault(vault.id);
    expect(view.members.map((member) => member.userId)).toEqual([alice.userId]);
    expect(view.rotationDue).toBe(true);
    expect(
      contentOf(await alice.session.readSection(vault.id, nodeIdFor(node), 'general')),
    ).toEqual({
      by: 'bob',
    });
    expect((await alice.session.rotate(vault.id)).rotationDue).toBe(false);
  });

  it('replaced keys are recorded in every vault; a member skipped by a rotation gets the key from an admin', async () => {
    const alice = await user();
    const bob = await user();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const node = await bob.session.createNode(vault.id, 'record');
    await bob.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: { before: true },
    });

    const replaced = await bob.client.replaceKeys({
      recoveryKeyCode: bob.recoveryKeyCode,
      newPassword: 'new keys',
    });
    expect(replaced.failedVaults).toEqual([]);
    expect(replaced.session.keyVersion).toBe(2);

    const view = await alice.session.openVault(vault.id);
    expect(view.members.find((member) => member.userId === bob.userId)?.keyVersion).toBe(2);
    expect(view.rotationDue).toBe(true);
    expect(
      contentOf(await alice.session.readSection(vault.id, nodeIdFor(node), 'general')),
    ).toEqual({
      before: true,
    });
    await replaced.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: { after: true },
    });
    expect(
      contentOf(await alice.session.readSection(vault.id, nodeIdFor(node), 'general')),
    ).toEqual({
      after: true,
    });
  });

  it('a member whose replacement a rotation skipped records it without a key, then gets one from an admin', async () => {
    const alice = await user();
    const storage = createMemoryStorage();
    const bobId = crypto.randomUUID();
    let blocked: string | undefined;
    const bobClient = clientFor(
      bobId,
      storage,
      (request) =>
        blocked !== undefined &&
        request.method === 'POST' &&
        request.url.endsWith(`/vaults/${blocked}/key-replacements`),
    );
    const bob = {
      userId: bobId,
      client: bobClient,
      ...(await bobClient.register({ userId: bobId, password: 'bob' })),
    };
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'viewer');

    // Recording fails here, as after a lost connection; the rotation then skips Bob's old keys.
    blocked = vault.id;
    const replaced = await bob.client.replaceKeys({
      recoveryKeyCode: bob.recoveryKeyCode,
      newPassword: 'new keys',
    });
    blocked = undefined;
    expect(replaced.failedVaults).toEqual([vault.id]);
    await alice.session.rotate(vault.id);
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'notes', {
      type: 'server',
      content: 'after the rotation',
    });

    await replaced.session.recordKeyReplacement(vault.id);
    await expect(
      replaced.session.readSection(vault.id, nodeIdFor(node), 'notes'),
    ).rejects.toBeInstanceOf(CloakKeyUnavailableError);
    expect(await alice.session.deliverEnvelopes(vault.id)).toBe(1);
    const fresh = await bob.client.unlock({
      password: 'new keys',
      secretKeyCode: replaced.secretKeyCode,
    });
    expect(contentOf(await fresh.readSection(vault.id, nodeIdFor(node), 'notes'))).toBe(
      'after the rotation',
    );
  });

  it('a user deletes their account: vaults go or are left, and the id never works again', async () => {
    const { storage, keys } = listedStorage();
    const userId = crypto.randomUUID();
    const client = clientFor(userId, storage);
    const registered = await client.register({
      userId,
      password: 'password',
      rememberSecretKey: true,
    });
    const alice: User = { userId, client, ...registered };
    const bob = await user();
    await meet(alice, bob);
    await meet(bob, alice);
    await alice.session.createVault();
    const shared = await alice.session.createVault();
    await alice.session.addMember(shared.id, bob.userId, 'editor');
    const bobs = await bob.session.createVault();
    await bob.session.addMember(bobs.id, alice.userId, 'editor');

    // Alice is the only owner of a vault Bob is in: nothing changes until she appoints another.
    await expect(alice.session.deleteAccount()).rejects.toMatchObject({
      name: 'CloakAccountNotEmptyError',
      vaultIds: [shared.id],
    });
    expect((await bob.session.openVault(bobs.id)).members).toHaveLength(2);

    await alice.session.setRole(shared.id, bob.userId, 'owner');
    await alice.session.deleteAccount();

    expect((await bob.session.openVault(shared.id)).members.map((m) => m.userId)).toEqual([
      bob.userId,
    ]);
    expect((await bob.session.openVault(bobs.id)).members.map((m) => m.userId)).toEqual([
      bob.userId,
    ]);
    expect(keys().filter((key) => key.startsWith(`cloak/v1/${cloakUserId(userId)}/`))).toEqual([]);
    await expectApiError(
      clientFor(userId).unlock({ password: 'password', secretKeyCode: alice.secretKeyCode }),
      'identity_deleted',
    );
    await expectApiError(
      clientFor(userId).register({ userId, password: 'again' }),
      'identity_deleted',
    );
  });

  it('tells before any password whether the user has no identity, has one, or had it erased', async () => {
    const userId = crypto.randomUUID();
    const client = clientFor(userId);
    expect(await client.identityStatus()).toBe('none');

    await client.register({ userId, password: 'correct horse' });
    expect(await client.identityStatus()).toBe('registered');
    expect(await clientFor(userId).identityStatus()).toBe('registered');

    await erase(userId);
    expect(await client.identityStatus()).toBe('deleted');
  });

  it('the host erases a user: they can do nothing, nobody seals to them, and an admin removes them', async () => {
    const alice = await user();
    const carol = await user();
    await meet(alice, carol);
    const vault = await alice.session.createVault();
    await alice.session.addMember(vault.id, carol.userId, 'editor');
    const node = await carol.session.createNode(vault.id, 'record');
    await carol.session.writeSection(vault.id, node, 'general', {
      type: 'note',
      content: 'by carol',
    });

    await erase(carol.userId);

    await expectApiError(carol.session.openVault(vault.id), 'identity_deleted');
    await expectApiError(
      clientFor(carol.userId).register({ userId: carol.userId, password: 'again' }),
      'identity_deleted',
    );
    const later = await alice.client.unlock({
      password: 'correct horse',
      secretKeyCode: alice.secretKeyCode,
    });
    // This device checked Carol's name before, so it still shows it beside the server's mark.
    expect((await later.openVault(vault.id)).members).toContainEqual(
      expect.objectContaining({ userId: carol.userId, deleted: true, role: 'editor' }),
    );
    await expectApiError(later.addMember(vault.id, carol.userId, 'viewer'), 'identity_deleted');
    // A rotation that keeps her seals the new key to nobody but Alice, which the server accepts.
    await later.rotate(vault.id);
    expect(contentOf(await later.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'by carol',
    );

    // A device that never knew her shows only that a deleted member is there.
    const elsewhere = await clientFor(alice.userId).unlock({
      password: 'correct horse',
      secretKeyCode: alice.secretKeyCode,
    });
    expect((await elsewhere.openVault(vault.id)).members).toContainEqual(
      expect.objectContaining({ userId: undefined, deleted: true }),
    );
    const removed = await elsewhere.rotate(vault.id, [], { removeDeleted: true });
    expect(removed.members.map((member) => member.userId)).toEqual([alice.userId]);
    expect(contentOf(await elsewhere.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'by carol',
    );
  });

  it('forgets a vault only on a signed fact, keeping its head, or when the user says so', async () => {
    const alice = await user();
    const { storage, keys } = listedStorage();
    const bobId = crypto.randomUUID();
    const bobClient = clientFor(bobId, storage);
    const bob: User = {
      userId: bobId,
      client: bobClient,
      ...(await bobClient.register({ userId: bobId, password: 'pw' })),
    };
    await meet(alice, bob);
    const records = (vaultId: string) =>
      keys()
        .filter((key) => key.includes(`/vaults/${vaultId}/`))
        .map((key) => key.slice(key.indexOf(`/vaults/${vaultId}/`) + `/vaults/${vaultId}/`.length));

    const left = await alice.session.createVault();
    await alice.session.addMember(left.id, bob.userId, 'editor');
    await bob.session.writeSection(
      left.id,
      await bob.session.createNode(left.id, 'note'),
      'general',
      {
        type: 'note',
        content: 'bob was here',
      },
    );
    expect(records(left.id)).toContain('snapshot');
    await bob.session.leave(left.id);
    expect(records(left.id)).toEqual(['head']);

    // Removed by an admin, Bob's device only sees the vault vanish: that proves nothing, so it
    // keeps everything until the user forgets the vault.
    const removed = await alice.session.createVault();
    await alice.session.addMember(removed.id, bob.userId, 'viewer');
    await bob.session.openVault(removed.id);
    await alice.session.rotate(removed.id, [bob.userId]);
    await expectApiError(bob.session.openVault(removed.id), 'not_found');
    expect(records(removed.id)).toContain('snapshot');
    await bob.session.forgetVault(removed.id);
    expect(records(removed.id)).toEqual([]);
  });

  it('closing a session waits for running work, then refuses everything and leaves storage sound', async () => {
    const storage = createMemoryStorage();
    const alice = await user('correct horse', storage);
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');

    const writing = alice.session.writeSection(vault.id, node, 'general', {
      type: 'note',
      content: 'written while closing',
    });
    const closing = alice.session.close();
    await expect(alice.session.openVault(vault.id)).rejects.toBeInstanceOf(CloakSessionClosedError);
    await writing;
    await closing;
    expect(alice.session.closed).toBe(true);

    // Every record the closed session kept still opens under the user's real key.
    const again = await alice.client.unlock({
      password: 'correct horse',
      secretKeyCode: alice.secretKeyCode,
    });
    expect(contentOf(await again.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'written while closing',
    );
  });

  it('a deleted section leaves checkpoints but keeps its versions, and can be written again', async () => {
    const alice = await user();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'one' });
    await alice.session.deleteSection(vault.id, node, 'general', 'note');
    await alice.session.rotate(vault.id);

    expect((await alice.session.readVault(vault.id)).sections).toEqual([]);
    const again = await alice.session.writeSection(vault.id, node, 'general', {
      type: 'note',
      content: 'two',
    });
    expect(again.dataVersion).toBe(3);
    await alice.session.rotate(vault.id);
    const device = await alice.client.unlock({
      password: 'correct horse',
      secretKeyCode: alice.secretKeyCode,
    });
    const read = await device.readVault(vault.id);
    expect(read.sections.map((section) => contentOf(section))).toEqual(['two']);
  });

  it('opens many vaults at once, and shares and unshares a group of them', async () => {
    const alice = await user();
    const bob = await user();
    const carol = await user();
    await meet(alice, bob);
    await meet(bob, alice);
    const project = [await alice.session.createVault(), await alice.session.createVault()];
    const bobs = await bob.session.createVault();
    await bob.session.addMember(bobs.id, alice.userId, 'viewer');

    // Alice may not add anyone to Bob's vault; the others still go ahead.
    await alice.session.confirmFingerprint(carol.userId, carol.session.fingerprint);
    const shared = await alice.session.addMemberToVaults(
      [...project.map((vault) => vault.id), bobs.id],
      carol.userId,
      'editor',
    );
    expect(shared.added).toEqual(project.map((vault) => vault.id));
    expect(shared.failed.map((failure) => failure.vaultId)).toEqual([bobs.id]);

    const opened = await carol.session.openVaults([...project.map((vault) => vault.id), bobs.id]);
    expect([...opened.values()].map((vault) => vault?.role)).toEqual([
      'editor',
      'editor',
      undefined,
    ]);

    // Removing goes everywhere or nowhere: Bob's vault refuses Alice, so nothing changes.
    await meet(bob, carol);
    await bob.session.addMember(bobs.id, carol.userId, 'viewer');
    await expect(
      alice.session.removeFromVaults(
        [...project.map((vault) => vault.id), bobs.id],
        [carol.userId],
      ),
    ).rejects.toMatchObject({ name: 'CloakApiError', vaultId: bobs.id });
    for (const vault of project)
      expect((await carol.session.openVault(vault.id)).role).toBe('editor');

    const removed = await alice.session.removeFromVaults(
      project.map((vault) => vault.id),
      [carol.userId],
    );
    expect(removed.map((vault) => vault.members.map((member) => member.userId))).toEqual([
      [alice.userId],
      [alice.userId],
    ]);
    const after = await carol.session.openVaults(project.map((vault) => vault.id));
    expect([...after.values()]).toEqual([undefined, undefined]);
  });

  it('the host purges a node only where the user may, and readers drop what was removed', async () => {
    const alice = await user();
    const bob = await user();
    await meet(bob, alice);
    await meet(alice, bob);
    const mine = await alice.session.createVault();
    const node = await alice.session.createNode(mine.id, 'record');
    await alice.session.writeSection(mine.id, node, 'general', { type: 'server', content: 'a' });
    // Alice shares the node into Bob's vault while an admin there, then is lowered to editor.
    const theirs = await bob.session.createVault();
    await bob.session.addMember(theirs.id, alice.userId, 'admin');
    await alice.session.shareNode(node, theirs.id, ['notes']);
    await bob.session.writeSection(theirs.id, node, 'notes', { type: 'server', content: 'b' });
    await bob.session.setRole(theirs.id, alice.userId, 'editor');
    const before = await alice.session.readVault(mine.id);
    expect(before.sections).toHaveLength(1);

    const origin = new URL(inject('cloakBaseUrl')).origin;
    const response = await fetch(
      `${origin}/dev/nodes/${nodeIdFor(node)}/purge?user=${encodeURIComponent(alice.userId)}`,
      { method: 'POST' },
    );
    expect(await response.json()).toEqual({ remainingVaultIds: [theirs.id] });

    expect((await alice.session.readVault(mine.id)).sections).toEqual([]);
    const feed = await alice.session.changes(mine.id, before.lastChangeSeq);
    expect(feed.removed.map((removal) => removal.name)).toEqual(['general']);
    expect((await bob.session.readVault(theirs.id)).sections).toHaveLength(1);
  });

  it('writes a node only where its owner put it, and shares end when taken back or when the owner goes', async () => {
    const alice = await user();
    const bob = await user();
    await meet(alice, bob);
    await meet(bob, alice);
    const home = await alice.session.createVault();
    const node = await alice.session.createNode(home.id, 'server-1');
    await alice.session.writeSection(home.id, node, 'general', { type: 'server', content: 'home' });

    // Bob's vault, where Alice is an editor: the node does not live there, so nothing is sent.
    const elsewhere = await bob.session.createVault();
    await bob.session.addMember(elsewhere.id, alice.userId, 'admin');
    await expect(
      alice.session.writeSection(elsewhere.id, node, 'login', { type: 'server', content: 'pw' }),
    ).rejects.toMatchObject({ name: 'CloakSectionError', reason: 'not_shared' });

    // Shared by name, the login goes there and Bob reads it; other names still do not.
    await alice.session.shareNode(node, elsewhere.id, ['login']);
    await alice.session.writeSection(elsewhere.id, node, 'login', {
      type: 'server',
      content: 'pw',
    });
    expect(contentOf(await bob.session.readSection(elsewhere.id, nodeIdFor(node), 'login'))).toBe(
      'pw',
    );
    await expect(
      alice.session.writeSection(elsewhere.id, node, 'general', { type: 'server', content: 'x' }),
    ).rejects.toMatchObject({ reason: 'not_shared' });

    // Taken back, the login stops counting for everyone, though Bob may have read it.
    await alice.session.unshareNode(node, elsewhere.id, ['login']);
    expect((await bob.session.readSection(elsewhere.id, nodeIdFor(node), 'login')).status).toBe(
      'refused',
    );

    // Shared again, then Bob removes Alice: her shares in his vault end with her membership.
    await alice.session.shareNode(node, elsewhere.id, ['login']);
    await alice.session.writeSection(elsewhere.id, node, 'login', {
      type: 'server',
      content: 'pw2',
    });
    await bob.session.rotate(elsewhere.id, [alice.userId]);
    expect(await bob.session.readSection(elsewhere.id, nodeIdFor(node), 'login')).toMatchObject({
      status: 'refused',
      reason: 'not_shared',
    });
    expect(contentOf(await alice.session.readSection(home.id, nodeIdFor(node), 'general'))).toBe(
      'home',
    );
  });

  it("deletes a vault with an owner's signature, which members verify and forget it by", async () => {
    const alice = await user();
    const bob = await user();
    await meet(alice, bob);
    const vault = await alice.session.createVault();
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const node = await bob.session.createNode(vault.id, 'record');
    await bob.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'x' });

    await alice.session.deleteVault(vault.id);

    const seen = await bob.session.openVault(vault.id);
    expect(seen.deleted).toBe(true);
    await expectApiError(
      bob.session.readSection(vault.id, nodeIdFor(node), 'general'),
      'not_found',
    );
    expect((await bob.session.listVaults()).items.map((item) => item.id)).not.toContain(vault.id);
  });

  it('lists vaults one was added to only once they are accepted', async () => {
    const alice = await user();
    const bob = await user();
    // Alice knows Bob, but Bob has not accepted anything from her yet.
    await alice.session.confirmFingerprint(bob.userId, bob.session.fingerprint);
    const first = await alice.session.createVault();
    await alice.session.addMember(first.id, bob.userId, 'viewer');

    expect((await bob.session.listVaults()).items).toEqual([]);
    const pending = await bob.session.listVaults({ pending: true });
    expect(pending.items.map((item) => [item.id, item.accepted, item.addedBy])).toEqual([
      [first.id, false, alice.userId],
    ]);
    await bob.session.acceptVault(first.id);
    expect((await bob.session.listVaults()).items.map((item) => item.id)).toEqual([first.id]);

    // Accepting a person accepts what they add later, too.
    await bob.session.acceptInvitationsFrom(alice.userId);
    const second = await alice.session.createVault();
    await alice.session.addMember(second.id, bob.userId, 'viewer');
    expect((await bob.session.listVaults()).items.map((item) => item.id).sort()).toEqual(
      [first.id, second.id].sort(),
    );
  });
});
