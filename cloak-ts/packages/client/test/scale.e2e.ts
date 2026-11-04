import { cloakUserId } from '@voirdev/cloak-crypto';
import { describe, expect, inject, it } from 'vitest';

import {
  createCloakClient,
  createMemoryStorage,
  type CloakClient,
  type CloakSession,
  type CloakStorage,
  type SectionChange,
} from '../src/index.ts';

/** A request a client sent, as the test sees it. */
interface Sent {
  readonly method: string;
  /** Path below `/cloak/v1`. */
  readonly path: string;
  readonly query: URLSearchParams;
}

/** A user's client that records its requests and may run a hook before one goes out. */
interface Counted {
  readonly userId: string;
  readonly client: CloakClient;
  readonly storage: CloakStorage;
  readonly session: CloakSession;
  readonly secretKeyCode: string;
  /** Requests sent so far; clear it to count a step. */
  readonly sent: Sent[];
  /** Runs before a request goes out; set by a test. */
  before: ((request: Request) => Promise<void>) | undefined;
}

/** A client of [userId] over [storage] that records into [sent] and runs [hooks]'s `before`. */
function recordingClient(
  userId: string,
  storage: CloakStorage,
  sent: Sent[],
  hooks: { before: ((request: Request) => Promise<void>) | undefined },
): CloakClient {
  return createCloakClient({
    baseUrl: inject('cloakBaseUrl'),
    storage,
    headers: () => ({ 'X-Cloak-Dev-User': userId }),
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      sent.push({
        method: request.method,
        path: url.pathname.replace(/^.*\/cloak\/v1/, ''),
        query: url.searchParams,
      });
      await hooks.before?.(request.clone());
      return fetch(request);
    },
  });
}

/** Registers a user whose requests are recorded. */
async function counted(): Promise<Counted> {
  const userId = crypto.randomUUID();
  const storage = createMemoryStorage();
  const sent: Sent[] = [];
  const user = { before: undefined } as Counted;
  const client = recordingClient(userId, storage, sent, user);
  const registered = await client.register({ userId, password: 'password' });
  return Object.assign(user, { userId, client, storage, sent, ...registered });
}

/** A second device of [user] with fresh local state, whose requests are recorded. */
async function anotherDevice(user: Counted): Promise<Counted> {
  const storage = createMemoryStorage();
  const sent: Sent[] = [];
  const device = { before: undefined } as Counted;
  const client = recordingClient(user.userId, storage, sent, device);
  const session = await client.unlock({ password: 'password', secretKeyCode: user.secretKeyCode });
  return Object.assign(device, {
    userId: user.userId,
    client,
    storage,
    sent,
    session,
    secretKeyCode: user.secretKeyCode,
  });
}

/** How many recorded requests match. */
function count(user: Counted, method: string, path: RegExp): number {
  return user.sent.filter((request) => request.method === method && path.test(request.path)).length;
}

/** Writes [total] new sections into a vault, 100 per batch, each batch into a new node. */
async function writeMany(session: CloakSession, vaultId: string, total: number): Promise<void> {
  for (let start = 0; start < total; start += 100) {
    const node = await session.createNode(vaultId, crypto.randomUUID());
    const changes: SectionChange[] = Array.from(
      { length: Math.min(100, total - start) },
      (_, index) => ({
        vaultId,
        node,
        name: `field_${String(index)}`,
        type: 'server',
        content: { index: start + index },
      }),
    );
    await session.writeSections(changes);
  }
}

describe('the client on large vaults', () => {
  it('builds checkpoints from headers and leaf lists, never from content or single proofs', async () => {
    const alice = await counted();
    const bob = await counted();
    const vault = await alice.session.createVault();
    await alice.session.confirmFingerprint(bob.userId, bob.session.fingerprint);
    await bob.session.acceptInvitationsFrom(alice.userId);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    await writeMany(bob.session, vault.id, 1_200);

    // No checkpoint follows these writes yet: judging them needs headers only, two pages for the
    // draft and one more, after the write pause, for what came since.
    alice.sent.length = 0;
    await alice.session.setRole(vault.id, bob.userId, 'viewer');
    expect(count(alice, 'GET', /\/section-headers$/)).toBe(3);
    expect(count(alice, 'GET', /\/sections$/)).toBe(0);
    expect(count(alice, 'POST', /\/checkpoint-proofs\/batch-get$/)).toBe(0);

    // Now 1 200 writes are judged by the checkpoint of the demotion: its leaf list, read once in
    // two pages, answers for all of them.
    await writeMany(alice.session, vault.id, 100);
    alice.sent.length = 0;
    await alice.session.rotate(vault.id);
    expect(count(alice, 'GET', /\/checkpoints\/\d+\/leaves$/)).toBe(2);
    expect(count(alice, 'POST', /\/checkpoint-proofs\/batch-get$/)).toBe(0);
    expect(count(alice, 'GET', /\/sections$/)).toBe(0);

    // A new device reads every section with one page per 100 writes and the two leaf lists.
    const device = await anotherDevice(alice);
    const changes = await device.session.changes(vault.id);
    expect(changes.sections).toHaveLength(1_300);
    expect(changes.sections.every((section) => section.status === 'ok')).toBe(true);
    expect(count(device, 'GET', /\/sections$/)).toBe(13);
    expect(count(device, 'GET', /\/checkpoints\/\d+\/leaves$/)).toBe(4);
    expect(count(device, 'POST', /\/checkpoint-proofs\/batch-get$/)).toBe(0);

    // One section is checked with proofs, all in one request.
    const single = changes.sections[0];
    if (single === undefined) throw new Error('No section');
    const reader = await anotherDevice(alice);
    expect((await reader.session.readSection(vault.id, single.nodeId, single.name)).status).toBe(
      'ok',
    );
    expect(count(reader, 'POST', /\/checkpoint-proofs\/batch-get$/)).toBe(1);
    expect(count(reader, 'GET', /\/checkpoints\/\d+\/leaves$/)).toBe(0);
  });

  it('continues a later session from the snapshot this device kept', async () => {
    const alice = await counted();
    const bob = await counted();
    const vault = await alice.session.createVault();
    await alice.session.confirmFingerprint(bob.userId, bob.session.fingerprint);
    await bob.session.acceptInvitationsFrom(alice.userId);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    await alice.session.setRole(vault.id, bob.userId, 'viewer');
    const verified = await alice.session.rotate(vault.id, [bob.userId]);

    alice.sent.length = 0;
    const later = await alice.client.unlock({
      password: 'password',
      secretKeyCode: alice.secretKeyCode,
    });
    expect(await later.openVault(vault.id)).toEqual(verified);
    const logReads = alice.sent.filter((request) => request.path.endsWith('/log'));
    expect(logReads).toHaveLength(1);
    expect(logReads[0]?.query.get('afterSeq')).toBe(String(verified.logSeq));
  });

  it('pauses writes while a checkpoint is finished, so a writer cannot make it fail', async () => {
    const alice = await counted();
    const bob = await counted();
    const vault = await alice.session.createVault();
    await alice.session.confirmFingerprint(bob.userId, bob.session.fingerprint);
    await bob.session.acceptInvitationsFrom(alice.userId);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    await writeMany(bob.session, vault.id, 150);

    // Bob writes while Alice's rotation is on its way; the pause holds his write back.
    const slipping = await bob.session.createNode(vault.id, 'slipping');
    const writes: Promise<unknown>[] = [];
    alice.before = (request) => {
      if (request.method === 'POST' && request.url.endsWith('/rotations') && writes.length < 2) {
        writes.push(
          bob.session.writeSection(vault.id, slipping, `slip_${String(writes.length)}`, {
            type: 'server',
            content: { slipped: writes.length },
          }),
        );
      }
      return Promise.resolve();
    };
    alice.sent.length = 0;
    const rotated = await alice.session.rotate(vault.id);
    alice.before = undefined;
    await Promise.all(writes);

    expect(rotated.keyVersion).toBe(2);
    expect(count(alice, 'POST', /\/rotations$/)).toBe(1);
    expect(count(alice, 'POST', /^\/write-pauses$/)).toBe(1);
    // The draft lists the vault; after the pause, only what came since is read.
    const headerReads = alice.sent.filter((request) => request.path.endsWith('/section-headers'));
    expect(headerReads[0]?.query.get('afterChange')).toBeNull();
    for (const read of headerReads.slice(1)) expect(read.query.get('afterChange')).not.toBeNull();

    const device = await anotherDevice(bob);
    const contents = await device.session.readVault(vault.id);
    expect(contents.sections).toHaveLength(151);
    expect(contents.sections.every((section) => section.status === 'ok')).toBe(true);
  });

  it('reads a vault again from what the device kept, checking signatures only once', async () => {
    const alice = await counted();
    const vault = await alice.session.createVault();
    await writeMany(alice.session, vault.id, 300);

    const device = await anotherDevice(alice);
    expect((await device.session.readVault(vault.id)).sections).toHaveLength(300);
    expect(count(device, 'GET', /\/sections$/)).toBe(3);

    // A later session on the same device reads nothing but the news.
    device.sent.length = 0;
    const later = await device.client.unlock({
      password: 'password',
      secretKeyCode: device.secretKeyCode,
    });
    await writeMany(alice.session, vault.id, 5);
    const read = await later.readVault(vault.id);
    expect(read.sections).toHaveLength(305);
    expect(count(device, 'GET', /\/sections$/)).toBe(1);

    // A checkpoint makes the device judge what it kept again, from the leaf list.
    await alice.session.rotate(vault.id);
    device.sent.length = 0;
    const judged = await later.readVault(vault.id);
    expect(judged.sections.every((section) => section.status === 'ok')).toBe(true);
    expect(count(device, 'GET', /\/checkpoints\/\d+\/leaves$/)).toBe(1);

    // A kept bucket lost, or put back from an older copy, only makes the device read more.
    const cache = `cloak/v1/${cloakUserId(device.userId)}/vaults/${vault.id}/cache/`;
    for (let bucket = 0; bucket < 64; bucket += 2)
      await device.storage.delete(`${cache}${String(bucket)}`);
    device.sent.length = 0;
    expect((await later.readVault(vault.id)).sections).toHaveLength(305);
    expect(count(device, 'GET', /\/sections$/)).toBe(4);
  });
});
