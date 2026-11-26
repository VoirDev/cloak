import {
  cloakUserId,
  createIdentity,
  deriveMasterKey,
  entryHash,
  fromBase64Url,
  fromSecretKeyCode,
  generateVaultKey,
  headerWriteHash,
  keysDigest,
  openPrivateKeyBundle,
  randomBytes,
  sealEnvelope,
  sectionCiphertextHash,
  signLogEntry,
  signSectionWrite,
  toBase64Url,
  type IdentitySecrets,
  type LogEntryFields,
  type SectionWriteFields,
} from '@voirdev/cloak-crypto';
import { describe, expect, inject, it } from 'vitest';

import {
  CloakFingerprintRequiredError,
  CloakKeyChangedError,
  createCloakClient,
  createMemoryStorage,
  isCloakApiError,
  nodeIdFor,
  type CloakClient,
  type CloakSession,
  type CloakStorage,
  type DecryptedSection,
} from '../src/index.ts';
import type { Schemas } from '../src/api.ts';
import { fromWireHeader, toWireWrite } from '../src/wire.ts';
import { register, replaceKeys } from './credentials.ts';

/**
 * A server that lies: before a request reaches the real server, [intercept] may answer it
 * instead; after, [rewrite] may replace the real response. Everything a hostile server can do to
 * a client, it can do through these.
 */
interface Hostile {
  /** Answers a request instead of the real server, for example to keep what a client signed. */
  intercept?: ((request: Request) => Promise<Response | undefined>) | undefined;
  /** Replaces a real response. */
  rewrite?: ((request: Request, response: Response) => Promise<Response | undefined>) | undefined;
}

/** A user's client behind a hostile server. */
interface Victim {
  /** Host user id. */
  readonly userId: string;
  /** Cloak user id, for protocol-level messages a hostile server forges. */
  readonly cloakId: string;
  readonly client: CloakClient;
  readonly hostile: Hostile;
  readonly storage: CloakStorage;
  readonly session: CloakSession;
  readonly secretKeyCode: string;
  readonly recoveryKeyCode: string;
}

/** The dev host trusts this header as the session. */
const USER_HEADER = 'X-Cloak-Dev-User';

/** Creates a client whose server is [hostile]. */
function clientBehind(userId: string, hostile: Hostile, storage: CloakStorage): CloakClient {
  return createCloakClient({
    baseUrl: inject('cloakBaseUrl'),
    storage,
    headers: () => ({ [USER_HEADER]: userId }),
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const answered = await hostile.intercept?.(request.clone());
      if (answered !== undefined) return answered;
      const response = await fetch(request.clone());
      return (await hostile.rewrite?.(request, response.clone())) ?? response;
    },
  });
}

/** Registers a user behind a server that is honest until a test turns it. */
async function victim(): Promise<Victim> {
  const userId = crypto.randomUUID();
  const hostile: Hostile = {};
  const storage = createMemoryStorage();
  const client = clientBehind(userId, hostile, storage);
  return {
    userId,
    cloakId: cloakUserId(userId),
    client,
    hostile,
    storage,
    ...(await register(client, { userId, password: 'password' })),
  };
}

/** A second device of [user], with its own hostile server and fresh local state. */
async function anotherDevice(
  user: Victim,
): Promise<{ readonly session: CloakSession; readonly hostile: Hostile }> {
  const hostile: Hostile = {};
  const client = clientBehind(user.userId, hostile, createMemoryStorage());
  return {
    session: await client.unlock({ password: 'password', secretKeyCode: user.secretKeyCode }),
    hostile,
  };
}

/** Lets [admin] add [member], as if they compared fingerprints in person. */
async function meet(admin: Victim, member: Victim): Promise<void> {
  await admin.session.confirmFingerprint(member.userId, member.session.fingerprint);
  // People who know each other accept what the other adds them to.
  await member.session.acceptInvitationsFrom(admin.userId);
}

/** A JSON response. */
function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Path of a request below `/cloak/v1`. */
function pathOf(request: Request): string {
  return new URL(request.url).pathname.replace(/^.*\/cloak\/v1/, '');
}

/** A write a client signed, kept by the hostile server instead of storing it. */
interface CapturedWrite {
  readonly vaultId: string;
  readonly nodeId: string;
  readonly sectionName: string;
  readonly input: Schemas['SectionWriteInput'];
}

/** Makes [hostile] keep the next section write instead of letting it through. */
function captureNextWrite(hostile: Hostile): Promise<CapturedWrite> {
  return new Promise((resolve) => {
    hostile.intercept = async (request) => {
      const match = /^\/vaults\/([^/]+)\/sections\/([^/]+)\/([^/]+)$/.exec(pathOf(request));
      if (request.method !== 'PUT' || match === null) return undefined;
      hostile.intercept = undefined;
      const [, vaultId = '', nodeId = '', sectionName = ''] = match;
      resolve({
        vaultId,
        nodeId,
        sectionName,
        input: (await request.json()) as Schemas['SectionWriteInput'],
      });
      return json(
        {
          type: 'urn:cloak:problem:internal_error',
          title: 'Internal error',
          status: 500,
          code: 'internal_error',
        },
        500,
      );
    };
  });
}

/** What a server would return for a captured write, as if it had stored it. */
function served(captured: CapturedWrite, writerUserId: string): Schemas['SectionWrite'] {
  const { ciphertext } = captured.input;
  const write: Schemas['SectionWrite'] = {
    ...captured.input,
    ...(ciphertext === undefined
      ? {}
      : { ciphertextHash: toBase64Url(sectionCiphertextHash(fromBase64Url(ciphertext))) }),
    vaultId: captured.vaultId,
    nodeId: captured.nodeId,
    sectionName: captured.sectionName,
    writerUserId,
    // A placeholder of the right size; the hash is computed from the header below.
    writeHash: toBase64Url(new Uint8Array(32)),
    changeSeq: 999,
    writtenAt: new Date().toISOString(),
  };
  return { ...write, writeHash: toBase64Url(headerWriteHash(fromWireHeader(write))) };
}

/** Makes [hostile] serve [write] as the latest write of its section. */
function serveSection(hostile: Hostile, write: Schemas['SectionWrite']): void {
  hostile.rewrite = (request) =>
    Promise.resolve(
      request.method === 'GET' &&
        pathOf(request) === `/vaults/${write.vaultId}/sections/${write.nodeId}/${write.sectionName}`
        ? json(write)
        : undefined,
    );
}

/** Makes [hostile] show a vault's log only up to [seq], as if nothing came after. */
function hideLogAfter(hostile: Hostile, vaultId: string, seq: number, role: string): void {
  hostile.rewrite = async (request, response) => {
    const path = pathOf(request);
    if (request.method !== 'GET') return undefined;
    if (path === `/vaults/${vaultId}/log`) {
      const page = (await response.json()) as Schemas['VaultLogPage'];
      return json({ items: page.items.filter((entry) => entry.seq <= seq), headSeq: seq });
    }
    if (path === `/vaults/${vaultId}`) {
      const view = (await response.json()) as Schemas['Vault'];
      const log = await fetch(`${inject('cloakBaseUrl')}/vaults/${vaultId}/log?limit=100`, {
        headers: request.headers,
      });
      const head = ((await log.json()) as Schemas['VaultLogPage']).items.find(
        (entry) => entry.seq === seq,
      );
      return json({
        ...view,
        logSeq: seq,
        logHeadHash: head?.entryHash,
        role,
        keyVersion: head?.keyVersion,
      });
    }
    return undefined;
  };
}

/** A problem response with [code]. */
function problem(code: string, status: number): Response {
  return json({ type: `urn:cloak:problem:${code}`, title: code, status, code }, status);
}

/** Reads the stored latest write of a section as [userId] sees it, past any hostile server. */
async function storedWrite(
  userId: string,
  vaultId: string,
  nodeId: string,
  name: string,
): Promise<Schemas['SectionWrite']> {
  const response = await fetch(
    `${inject('cloakBaseUrl')}/vaults/${vaultId}/sections/${nodeId}/${name}`,
    { headers: { [USER_HEADER]: userId } },
  );
  return (await response.json()) as Schemas['SectionWrite'];
}

/** Reads a vault's view as [userId] sees it, past any hostile server. */
async function viewOf(userId: string, vaultId: string): Promise<Schemas['Vault']> {
  const response = await fetch(`${inject('cloakBaseUrl')}/vaults/${vaultId}`, {
    headers: { [USER_HEADER]: userId },
  });
  return (await response.json()) as Schemas['Vault'];
}

/** Opens [user]'s current private keys with the password and secret key, as a thief of both could. */
async function openSecrets(user: Victim): Promise<IdentitySecrets> {
  const response = await fetch(`${inject('cloakBaseUrl')}/identity`, {
    headers: { [USER_HEADER]: user.userId },
  });
  const identity = (await response.json()) as Schemas['Identity'];
  const masterKey = await deriveMasterKey({
    password: 'password',
    secretKey: fromSecretKeyCode(user.secretKeyCode),
    userId: user.cloakId,
    kdf: { ...identity.kdf, salt: fromBase64Url(identity.kdf.salt) },
  });
  return openPrivateKeyBundle(masterKey, identity.keys, fromBase64Url(identity.privateKeyBundle));
}

/**
 * A write of [writer]'s, signed with the secrets of their key version 1, after [previous] and
 * citing the head of [view], as the server would serve it; its ciphertext is noise of a valid
 * size, since nobody reads it.
 */
function signedByHand(
  secrets: IdentitySecrets,
  writer: Victim,
  previous: Schemas['SectionWrite'],
  view: Schemas['Vault'],
): Schemas['SectionWrite'] {
  const fields: SectionWriteFields = {
    vaultId: previous.vaultId,
    nodeId: previous.nodeId,
    sectionName: previous.sectionName,
    vaultKeyVersion: view.keyVersion,
    nodeType: previous.nodeType,
    homeVaultId: previous.homeVaultId,
    ownerUserId: previous.ownerUserId,
    nodeKey: previous.nodeKey,
    dataVersion: previous.dataVersion + 1,
    deleted: false,
    logSeq: view.logSeq,
    logHeadHash: fromBase64Url(view.logHeadHash),
    previousWriteHash: fromBase64Url(previous.writeHash),
    writerUserId: writer.cloakId,
    writerKeyVersion: 1,
    ciphertext: randomBytes(41 + 256),
  };
  const input = toWireWrite(fields, signSectionWrite(fields, secrets.signingSeed));
  const { vaultId, nodeId, sectionName } = fields;
  return served({ vaultId, nodeId, sectionName, input }, writer.cloakId);
}

/** The reason a section was refused. */
function refusal(section: DecryptedSection): string {
  return section.status === 'refused' ? section.reason : section.status;
}

/** A keys batch in which [impostor]'s first version stands for [person]'s keys. */
function withImpostor(
  batch: Schemas['BatchGetUserKeysResponse'],
  person: Victim,
  impostor: Awaited<ReturnType<typeof createIdentity>>,
): Schemas['BatchGetUserKeysResponse'] {
  return {
    ...batch,
    items: batch.items.map((item) =>
      item.userId !== person.cloakId
        ? item
        : {
            userId: person.cloakId,
            hostUserId: person.userId,
            deleted: false,
            versions: [
              {
                keys: {
                  userId: person.cloakId,
                  keyVersion: 1,
                  cryptoSuite: 1,
                  encryptionPublicKey: toBase64Url(impostor.keys.encryptionPublicKey),
                  signingPublicKey: toBase64Url(impostor.keys.signingPublicKey),
                  recoverySigningPublicKey: toBase64Url(impostor.keys.recoverySigningPublicKey),
                },
                signature: toBase64Url(impostor.statement.signature),
              },
            ],
          },
    ),
  };
}

/** Whether [request] asks for people's keys. */
function asksForKeys(request: Request): boolean {
  return request.method === 'POST' && pathOf(request) === '/users/keys/batch-get';
}

describe('a malicious server', () => {
  it('cannot hand a member a vault key of its choosing', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: 'secret',
    });

    const device = await anotherDevice(alice);
    const ownKeys = alice.session.keyVersion;
    const keys = (await (
      await fetch(`${inject('cloakBaseUrl')}/users/${alice.cloakId}/keys`, {
        headers: { [USER_HEADER]: alice.userId },
      })
    ).json()) as Schemas['UserKeys'];
    const publicKey = fromBase64Url(keys.versions[0]?.keys.encryptionPublicKey ?? '');
    const chosen = await sealEnvelope(
      publicKey,
      vault.id,
      1,
      { userId: alice.cloakId, userKeyVersion: ownKeys },
      generateVaultKey(),
    );
    device.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}`) return undefined;
      return json({
        ...((await response.json()) as Schemas['Vault']),
        keyEnvelope: toBase64Url(chosen),
      });
    };

    await expect(
      device.session.readSection(vault.id, nodeIdFor(node), 'general'),
    ).rejects.toMatchObject({
      reason: 'key_mismatch',
    });
  });

  it('cannot add a member nobody authorized', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const device = await anotherDevice(alice);
    const intruder = await createIdentity(crypto.randomUUID(), 'intruder');
    const forger = await createIdentity(alice.cloakId, 'forger');

    device.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}/log`)
        return undefined;
      const page = (await response.json()) as Schemas['VaultLogPage'];
      const last = page.items.at(-1);
      if (last === undefined) return undefined;
      const fields: LogEntryFields = {
        vaultId: vault.id,
        seq: last.seq + 1,
        previousHash: fromBase64Url(last.entryHash),
        kind: 'member_added',
        subjectUserId: intruder.keys.userId,
        role: 'admin',
        keyVersion: last.keyVersion,
        subjectKeys: keysDigest(intruder.keys),
        subjectKeyVersion: 1,
        requestEnd: true,
        authorUserId: alice.cloakId,
        authorKeyVersion: 1,
      };
      const forged: Schemas['LogEntry'] = {
        seq: fields.seq,
        kind: 'member_added',
        subjectUserId: intruder.keys.userId,
        role: 'admin',
        keyVersion: fields.keyVersion,
        subjectKeys: toBase64Url(keysDigest(intruder.keys)),
        subjectKeyVersion: 1,
        requestEnd: true,
        authorKeyVersion: 1,
        signature: toBase64Url(signLogEntry(fields, forger.secrets.signingSeed)),
        authorUserId: alice.cloakId,
        entryHash: toBase64Url(entryHash(fields)),
        createdAt: last.createdAt,
      };
      return json({ items: [...page.items, forged], headSeq: fields.seq });
    };

    await expect(device.session.openVault(vault.id)).rejects.toMatchObject({
      name: 'CloakVaultLogError',
      reason: 'bad_signature',
      seq: 2,
    });
  });

  it('cannot swap the keys of a person this device pinned', async () => {
    const alice = await victim();
    const carol = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, carol);
    const impostor = await createIdentity(carol.cloakId, 'impostor');

    alice.hostile.rewrite = async (request, response) =>
      asksForKeys(request)
        ? json(
            withImpostor(
              (await response.json()) as Schemas['BatchGetUserKeysResponse'],
              carol,
              impostor,
            ),
          )
        : undefined;

    await expect(alice.session.addMember(vault.id, carol.userId, 'viewer')).rejects.toBeInstanceOf(
      CloakKeyChangedError,
    );
  });

  it("cannot pass off another person's identity as the signed-in user's", async () => {
    const alice = await victim();
    const carol = await victim();
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== '/identity') return undefined;
      const identity = (await response.json()) as Schemas['Identity'];
      return json({ ...identity, hostUserId: carol.userId });
    };

    const unexpected = { name: 'CloakApiError', code: 'unexpected_response' };
    await expect(alice.client.identityStatus()).rejects.toMatchObject(unexpected);
    await expect(
      alice.client.unlock({ password: 'password', secretKeyCode: alice.secretKeyCode }),
    ).rejects.toMatchObject(unexpected);
  });

  it('cannot get a backdated write of a demoted editor accepted', async () => {
    const alice = await victim();
    const bob = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const node = await bob.session.createNode(vault.id, 'record');
    await bob.session.writeSection(vault.id, node, 'general', {
      type: 'server',
      content: 'honest',
    });
    const beforeDemotion = (await alice.session.openVault(vault.id)).logSeq;
    await alice.session.setRole(vault.id, bob.userId, 'viewer');

    // Bob, with the server's help, signs a write that cites the head before his demotion.
    const bobDevice = await anotherDevice(bob);
    hideLogAfter(bobDevice.hostile, vault.id, beforeDemotion, 'editor');
    const captured = captureNextWrite(bobDevice.hostile);
    await expect(
      bobDevice.session.writeSection(vault.id, node, 'general', {
        type: 'server',
        content: 'backdated',
      }),
    ).rejects.toThrow();

    serveSection(alice.hostile, served(await captured, bob.cloakId));
    expect(refusal(await alice.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'not_in_checkpoint',
    );
  });

  it('cannot roll a section back, or fork it, on a device that saw it', async () => {
    const alice = await victim();
    const bob = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const node = await bob.session.createNode(vault.id, 'record');
    await bob.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'v1' });
    const first = (await (
      await fetch(
        `${inject('cloakBaseUrl')}/vaults/${vault.id}/sections/${nodeIdFor(node)}/general`,
        {
          headers: { [USER_HEADER]: alice.userId },
        },
      )
    ).json()) as Schemas['SectionWrite'];

    // A second version 2, validly signed but never stored: the server keeps it for later.
    const bobDevice = await anotherDevice(bob);
    const captured = captureNextWrite(bobDevice.hostile);
    await expect(
      bobDevice.session.writeSection(vault.id, node, 'general', {
        type: 'server',
        content: 'v2 elsewhere',
      }),
    ).rejects.toThrow();
    const fork = served(await captured, bob.cloakId);

    await bob.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'v2' });
    expect((await alice.session.readSection(vault.id, nodeIdFor(node), 'general')).status).toBe(
      'ok',
    );

    serveSection(alice.hostile, first);
    expect(refusal(await alice.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'rollback',
    );
    serveSection(alice.hostile, fork);
    expect(refusal(await alice.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'fork',
    );
  });

  it('cannot roll back or fork a vault log on a device that verified it', async () => {
    const alice = await victim();
    const bob = await victim();
    const carol = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await meet(alice, carol);
    await alice.session.addMember(vault.id, bob.userId, 'admin');
    const head = (await alice.session.addMember(vault.id, carol.userId, 'viewer')).logSeq;

    const rolledBack = await alice.client.unlock({
      password: 'password',
      secretKeyCode: alice.secretKeyCode,
    });
    hideLogAfter(alice.hostile, vault.id, head - 1, 'owner');
    await expect(rolledBack.openVault(vault.id)).rejects.toMatchObject({ reason: 'rollback' });

    // Bob, shown the log without Carol's entry, validly signs another entry at the same position.
    alice.hostile.rewrite = undefined;
    const bobDevice = await anotherDevice(bob);
    await bobDevice.session.confirmFingerprint(carol.userId, carol.session.fingerprint);
    hideLogAfter(bobDevice.hostile, vault.id, head - 1, 'admin');
    let branch: Schemas['LogEntryInput'] | undefined;
    bobDevice.hostile.intercept = async (request) => {
      if (request.method !== 'POST' || pathOf(request) !== `/vaults/${vault.id}/members`)
        return undefined;
      branch = ((await request.json()) as Schemas['AddMemberRequest']).log;
      return json(
        {
          type: 'urn:cloak:problem:internal_error',
          title: 'Internal error',
          status: 500,
          code: 'internal_error',
        },
        500,
      );
    };
    await expect(bobDevice.session.addMember(vault.id, carol.userId, 'editor')).rejects.toThrow();
    if (branch === undefined) throw new Error('No entry was signed');
    const forked = branch;

    // A device that lost its snapshot, but kept the head it verified, reads the log from seq 1.
    const withoutSnapshots: CloakStorage = {
      get: (key) =>
        key.endsWith('/snapshot') ? Promise.resolve(undefined) : alice.storage.get(key),
      set: (key, value) => alice.storage.set(key, value),
      delete: (key) => alice.storage.delete(key),
      deletePrefix: (prefix) => alice.storage.deletePrefix(prefix),
      keys: (prefix) => alice.storage.keys(prefix),
    };
    const forkedSession = await clientBehind(alice.userId, alice.hostile, withoutSnapshots).unlock({
      password: 'password',
      secretKeyCode: alice.secretKeyCode,
    });
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || !pathOf(request).startsWith(`/vaults/${vault.id}`))
        return undefined;
      if (pathOf(request).endsWith('/log')) {
        const page = (await response.json()) as Schemas['VaultLogPage'];
        const previous = page.items.find((entry) => entry.seq === head - 1);
        const real = page.items.find((entry) => entry.seq === head);
        if (previous === undefined || real === undefined) return undefined;
        const fields: LogEntryFields = {
          vaultId: vault.id,
          seq: head,
          previousHash: fromBase64Url(previous.entryHash),
          kind: forked.kind,
          subjectUserId: forked.subjectUserId,
          role: forked.role,
          keyVersion: forked.keyVersion,
          subjectKeys:
            forked.subjectKeys === undefined ? undefined : fromBase64Url(forked.subjectKeys),
          subjectKeyVersion: forked.subjectKeyVersion,
          requestEnd: true,
          authorUserId: bob.cloakId,
          authorKeyVersion: forked.authorKeyVersion,
        };
        const entry = {
          ...forked,
          authorUserId: bob.cloakId,
          entryHash: toBase64Url(entryHash(fields)),
          createdAt: real.createdAt,
        };
        return json({
          items: page.items.map((item) => (item.seq === head ? entry : item)),
          headSeq: page.headSeq,
        });
      }
      return undefined;
    };
    // The branch is validly signed, so only the head this device kept gives it away.
    await expect(forkedSession.openVault(vault.id)).rejects.toMatchObject({
      name: 'CloakVaultLogError',
      reason: 'rollback',
    });
  });

  it('cannot lie about a member role or the head', async () => {
    const alice = await victim();
    const carol = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, carol);
    await alice.session.addMember(vault.id, carol.userId, 'viewer');

    carol.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}`) return undefined;
      return json({ ...((await response.json()) as Schemas['Vault']), role: 'owner' });
    };

    await expect(carol.session.openVault(vault.id)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
  });

  it('cannot get writes signed with replaced keys accepted', async () => {
    const alice = await victim();
    const bob = await victim();
    const recorded = await alice.session.createVault();
    const withheld = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(recorded.id, bob.userId, 'editor');
    await alice.session.addMember(withheld.id, bob.userId, 'editor');
    // The device whose keys leak has written before, so it holds both vault keys.
    const oldKeys = await anotherDevice(bob);
    const oldSecrets = await openSecrets(bob);
    // Alice creates the nodes, so the logs hold no entry of Bob's old keys, only his writes.
    const inRecordedNode = await alice.session.createNode(recorded.id, 'record');
    const inWithheldNode = await alice.session.createNode(withheld.id, 'record');
    await oldKeys.session.writeSection(recorded.id, inRecordedNode, 'general', {
      type: 'server',
      content: 'before',
    });
    await oldKeys.session.writeSection(withheld.id, inWithheldNode, 'general', {
      type: 'server',
      content: 'before',
    });

    // Bob replaces his keys; the server records the replacement in one vault and withholds it in
    // the other.
    bob.hostile.intercept = (request) =>
      Promise.resolve(
        request.method === 'POST' && pathOf(request) === `/vaults/${withheld.id}/key-replacements`
          ? json(
              {
                type: 'urn:cloak:problem:internal_error',
                title: 'Internal error',
                status: 500,
                code: 'internal_error',
              },
              500,
            )
          : undefined,
      );
    const replaced = await replaceKeys(bob.client, {
      recoveryKeyCode: bob.recoveryKeyCode,
      newPassword: 'new',
    });
    bob.hostile.intercept = undefined;
    expect(replaced.failedVaults).toEqual([withheld.id]);

    // A thief with Bob's old keys writes in both vaults; the server serves what he signed. The
    // client of the old keys itself refuses to write where the log no longer commits them, so the
    // thief signs that write by hand, on the head that recorded the replacement.
    await expect(
      oldKeys.session.writeSection(recorded.id, inRecordedNode, 'general', {
        type: 'server',
        content: 'thief',
      }),
    ).rejects.toMatchObject({ reason: 'not_an_editor' });
    const recordedWrite = signedByHand(
      oldSecrets,
      bob,
      await storedWrite(alice.userId, recorded.id, nodeIdFor(inRecordedNode), 'general'),
      await viewOf(alice.userId, recorded.id),
    );
    const inWithheld = captureNextWrite(oldKeys.hostile);
    await expect(
      oldKeys.session.writeSection(withheld.id, inWithheldNode, 'general', {
        type: 'server',
        content: 'thief',
      }),
    ).rejects.toThrow();
    const withheldWrite = served(await inWithheld, bob.cloakId);

    const reader = await anotherDevice(alice);
    serveSection(reader.hostile, recordedWrite);
    expect(
      refusal(await reader.session.readSection(recorded.id, nodeIdFor(inRecordedNode), 'general')),
    ).toBe('not_an_editor');
    serveSection(reader.hostile, withheldWrite);
    expect(
      refusal(await reader.session.readSection(withheld.id, nodeIdFor(inWithheldNode), 'general')),
    ).toBe('superseded_keys');
  });

  it('cannot echo a write other than the one signed', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'PUT' || !pathOf(request).startsWith(`/vaults/${vault.id}/sections/`))
        return undefined;
      const write = (await response.json()) as Schemas['SectionWrite'];
      return json({ ...write, dataVersion: write.dataVersion + 1 });
    };

    await expect(
      alice.session.writeSection(vault.id, node, 'general', {
        type: 'server',
        content: 'mine',
      }),
    ).rejects.toMatchObject({ reason: 'state_mismatch' });
  });

  it('cannot serve a write under another address', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const real = await alice.session.createNode(vault.id, 'real');
    const asked = nodeIdFor(await alice.session.createNode(vault.id, 'asked'));
    await alice.session.writeSection(vault.id, real, 'general', { type: 'server', content: 'a' });
    const write = await storedWrite(alice.userId, vault.id, nodeIdFor(real), 'general');

    const reader = await anotherDevice(alice);
    reader.hostile.rewrite = (request) =>
      Promise.resolve(
        request.method === 'GET' &&
          pathOf(request) === `/vaults/${vault.id}/sections/${asked}/general`
          ? json(write)
          : undefined,
      );
    await expect(reader.session.readSection(vault.id, asked, 'general')).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
  });

  it('cannot roll back, fork or swap the latest writes a writer chains to', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    const other = nodeIdFor(await alice.session.createNode(vault.id, 'other'));
    await alice.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'v1' });
    const write = () =>
      alice.session.writeSections([
        { vaultId: vault.id, node, name: 'general', type: 'server', content: 'v2' },
        { vaultId: vault.id, node, name: 'notes', type: 'server', content: 'new' },
      ]);
    const lie = (change: (answer: Schemas['BatchGetSectionHeadersResponse']) => unknown): void => {
      alice.hostile.rewrite = async (request, response) => {
        if (request.method !== 'POST' || pathOf(request) !== '/section-headers/batch-get')
          return undefined;
        return json(change((await response.json()) as Schemas['BatchGetSectionHeadersResponse']));
      };
    };
    const stored = await fetch(`${inject('cloakBaseUrl')}/section-headers/batch-get`, {
      method: 'POST',
      headers: { [USER_HEADER]: alice.userId, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sections: [{ vaultId: vault.id, nodeId: nodeIdFor(node), sectionName: 'general' }],
      }),
    });
    const [header] = ((await stored.json()) as Schemas['BatchGetSectionHeadersResponse']).items;
    if (header === undefined) throw new Error('The section was not written');
    const notes = { vaultId: vault.id, nodeId: nodeIdFor(node), sectionName: 'notes' };

    // A section this device saw, claimed absent; another write of the version it saw.
    lie(() => ({ items: [], missing: [header, notes] }));
    await expect(write()).rejects.toMatchObject({ reason: 'rollback' });
    lie(() => ({ items: [{ ...header, ciphertextHash: header.writeHash }], missing: [notes] }));
    await expect(write()).rejects.toMatchObject({ reason: 'fork' });

    // An answer for another section, twice for one, short of one, or for one never asked.
    const misplaced = [
      { items: [{ ...header, nodeId: other }], missing: [notes] },
      { items: [header, header], missing: [notes] },
      { items: [header], missing: [] },
      { items: [header], missing: [notes, { ...notes, sectionName: 'extra' }] },
    ];
    for (const answer of misplaced) {
      lie(() => answer);
      await expect(write()).rejects.toMatchObject({ reason: 'state_mismatch' });
    }

    // A lookup refused as not found is a failure, never a list of new sections.
    let wrote = false;
    alice.hostile.intercept = (request) => {
      const path = pathOf(request);
      if (path === '/sections/batch-write') wrote = true;
      return Promise.resolve(
        path === '/section-headers/batch-get' ? problem('not_found', 404) : undefined,
      );
    };
    alice.hostile.rewrite = undefined;
    await expect(write()).rejects.toMatchObject({ code: 'not_found' });
    expect(wrote).toBe(false);

    alice.hostile.intercept = undefined;
    const written = await write();
    expect(written.map((info) => info.dataVersion)).toEqual([2, 1]);
  });

  it('cannot make a write stand by claiming nodes were created', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    alice.hostile.intercept = async (request) => {
      if (pathOf(request) !== `/vaults/${vault.id}/node-entries/batch-append`) return undefined;
      const view = await fetch(`${inject('cloakBaseUrl')}/vaults/${vault.id}`, {
        headers: { [USER_HEADER]: alice.userId },
      });
      return json(await view.json());
    };

    const [node] = await alice.session.createNodes(vault.id, ['record']);
    if (node === undefined) throw new Error('No node');
    alice.hostile.intercept = undefined;
    await expect(
      alice.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'x' }),
    ).rejects.toMatchObject({ reason: 'not_shared' });
  });

  it('cannot get a malformed response used', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}`) return undefined;
      const view = (await response.json()) as Schemas['Vault'];
      return json({ ...view, id: view.id.toUpperCase() });
    };

    await expect(alice.session.openVault(vault.id)).rejects.toMatchObject({
      name: 'CloakApiError',
      code: 'unexpected_response',
    });
  });

  it('cannot get a key, signature or listing of the wrong size or shape used', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const unexpected = { name: 'CloakApiError', code: 'unexpected_response' };
    /** Makes [hostile] answer [method] [path] with what [forge] makes of the real answer. */
    const forging = (
      hostile: Hostile,
      method: string,
      path: string,
      forge: (served: Record<string, unknown>) => unknown,
    ) => {
      hostile.rewrite = async (request, response) =>
        request.method === method && pathOf(request) === path
          ? json(forge((await response.json()) as Record<string, unknown>))
          : undefined;
    };
    /** [value], a base64url string, one byte short. */
    const short = (value: unknown) => (typeof value === 'string' ? value.slice(0, -2) : value);

    forging(alice.hostile, 'GET', '/identity', (identity) => ({
      ...identity,
      keys: {
        ...(identity['keys'] as Record<string, unknown>),
        signingPublicKey: short((identity['keys'] as Record<string, unknown>)['signingPublicKey']),
      },
    }));
    await expect(
      alice.client.unlock({ password: 'password', secretKeyCode: alice.secretKeyCode }),
    ).rejects.toMatchObject(unexpected);

    forging(alice.hostile, 'GET', '/vaults', (page) => ({ ...page, items: {} }));
    await expect(alice.session.listVaults()).rejects.toMatchObject(unexpected);
    alice.hostile.rewrite = undefined;

    const reader = await anotherDevice(alice);
    forging(reader.hostile, 'POST', '/users/keys/batch-get', (batch) => ({
      ...batch,
      items: (batch['items'] as Record<string, unknown>[]).map((item) => ({
        ...item,
        versions: (item['versions'] as Record<string, unknown>[]).map((version) => ({
          ...version,
          signature: short(version['signature']),
        })),
      })),
    }));
    await expect(reader.session.openVault(vault.id)).rejects.toMatchObject(unexpected);

    forging(reader.hostile, 'GET', `/vaults/${vault.id}/log`, (page) => ({
      ...page,
      items: (page['items'] as Record<string, unknown>[]).map((entry) => ({
        ...entry,
        signature: short(entry['signature']),
      })),
    }));
    await expect(reader.session.openVault(vault.id)).rejects.toMatchObject(unexpected);
  });

  it('cannot roll a section back to a write a later checkpoint superseded', async () => {
    const alice = await victim();
    const bob = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'editor');
    const node = await bob.session.createNode(vault.id, 'record');
    await bob.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'v1' });
    const first = await storedWrite(alice.userId, vault.id, nodeIdFor(node), 'general');
    await alice.session.rotate(vault.id);
    await bob.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'v2' });
    await alice.session.rotate(vault.id);

    // A device that never saw the section: the first checkpoint after v1 holds v1, the last v2.
    const reader = await anotherDevice(alice);
    serveSection(reader.hostile, first);
    expect(refusal(await reader.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'rollback',
    );
  });

  it('cannot collect a second signed version of a change by faking a conflict', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    let attempts = 0;
    alice.hostile.intercept = (request) => {
      if (request.method !== 'PUT' || !pathOf(request).startsWith(`/vaults/${vault.id}/sections/`))
        return Promise.resolve(undefined);
      attempts += 1;
      return Promise.resolve(problem('stale_head', 409));
    };

    await expect(
      alice.session.writeSection(vault.id, node, 'general', {
        type: 'server',
        content: 'once',
      }),
    ).rejects.toMatchObject({ code: 'stale_head' });
    expect(attempts).toBe(1);
  });

  it('cannot collect signed versions of a rotation by faking a checkpoint conflict', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'x' });
    let rotations = 0;
    alice.hostile.intercept = (request) => {
      if (request.method !== 'POST' || pathOf(request) !== `/vaults/${vault.id}/rotations`)
        return Promise.resolve(undefined);
      rotations += 1;
      return Promise.resolve(problem('checkpoint_conflict', 409));
    };
    // The server's change counter moves on every read, though no write came.
    let extra = 0;
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}/section-headers`)
        return undefined;
      const page = (await response.json()) as Schemas['SectionHeaderPage'];
      extra += 1;
      const last = page.lastChangeSeq + extra;
      return json({ ...page, throughChangeSeq: last, lastChangeSeq: last });
    };

    await expect(alice.session.rotate(vault.id)).rejects.toMatchObject({
      code: 'checkpoint_conflict',
    });
    expect(rotations).toBe(1);
  });

  it('cannot get a person met through a write that does not stand', async () => {
    const alice = await victim();
    const carol = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'general', { type: 'server', content: 'x' });
    const stored = await storedWrite(alice.userId, vault.id, nodeIdFor(node), 'general');
    const junk = { ...stored, writerUserId: carol.cloakId };
    const impostor = await createIdentity(carol.cloakId, 'impostor');

    // A write said to be Carol's, under keys the server chose for her.
    alice.hostile.rewrite = async (request, response) => {
      if (asksForKeys(request))
        return json(
          withImpostor(
            (await response.json()) as Schemas['BatchGetUserKeysResponse'],
            carol,
            impostor,
          ),
        );
      if (
        request.method === 'GET' &&
        pathOf(request) === `/vaults/${vault.id}/sections/${nodeIdFor(node)}/general`
      )
        return json({ ...junk, writeHash: toBase64Url(headerWriteHash(fromWireHeader(junk))) });
      return undefined;
    };
    expect(refusal(await alice.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'not_an_editor',
    );

    alice.hostile.rewrite = undefined;
    await expect(alice.session.addMember(vault.id, carol.userId, 'viewer')).rejects.toBeInstanceOf(
      CloakFingerprintRequiredError,
    );
  });

  it('cannot get a person met through a log entry that does not verify', async () => {
    const alice = await victim();
    const carol = await victim();
    const vault = await alice.session.createVault();
    const device = await anotherDevice(alice);
    const impostor = await createIdentity(carol.cloakId, 'impostor');
    const forger = await createIdentity(alice.cloakId, 'forger');

    // An entry adding Carol under the server's keys for her, signed by nobody in the vault.
    device.hostile.rewrite = async (request, response) => {
      if (asksForKeys(request))
        return json(
          withImpostor(
            (await response.json()) as Schemas['BatchGetUserKeysResponse'],
            carol,
            impostor,
          ),
        );
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}/log`)
        return undefined;
      const page = (await response.json()) as Schemas['VaultLogPage'];
      const last = page.items.at(-1);
      if (last === undefined) return undefined;
      const fields: LogEntryFields = {
        vaultId: vault.id,
        seq: last.seq + 1,
        previousHash: fromBase64Url(last.entryHash),
        kind: 'member_added',
        subjectUserId: carol.cloakId,
        role: 'viewer',
        keyVersion: last.keyVersion,
        subjectKeys: keysDigest(impostor.keys),
        subjectKeyVersion: 1,
        requestEnd: true,
        authorUserId: alice.cloakId,
        authorKeyVersion: 1,
      };
      const forged: Schemas['LogEntry'] = {
        seq: fields.seq,
        kind: 'member_added',
        subjectUserId: carol.cloakId,
        role: 'viewer',
        keyVersion: fields.keyVersion,
        subjectKeys: toBase64Url(keysDigest(impostor.keys)),
        subjectKeyVersion: 1,
        requestEnd: true,
        authorKeyVersion: 1,
        signature: toBase64Url(signLogEntry(fields, forger.secrets.signingSeed)),
        authorUserId: alice.cloakId,
        entryHash: toBase64Url(entryHash(fields)),
        createdAt: last.createdAt,
      };
      return json({ items: [...page.items, forged], headSeq: fields.seq });
    };
    await expect(device.session.openVault(vault.id)).rejects.toMatchObject({
      name: 'CloakVaultLogError',
    });

    device.hostile.rewrite = undefined;
    await expect(device.session.addMember(vault.id, carol.userId, 'viewer')).rejects.toBeInstanceOf(
      CloakFingerprintRequiredError,
    );
  });

  it('cannot get a person vouched for by a vault the user never accepted', async () => {
    const alice = await victim();
    const mallory = await victim();
    const carol = await victim();
    const own = await alice.session.createVault();
    // A vault an account of the server made, with Alice and Carol in it, that Alice never accepted.
    const trap = await mallory.session.createVault();
    await mallory.session.confirmFingerprint(alice.userId, alice.session.fingerprint);
    await mallory.session.confirmFingerprint(carol.userId, carol.session.fingerprint);
    await mallory.session.addMember(trap.id, alice.userId, 'viewer');
    await mallory.session.addMember(trap.id, carol.userId, 'viewer');

    await alice.session.openVault(trap.id);
    await expect(alice.session.addMember(own.id, carol.userId, 'viewer')).rejects.toBeInstanceOf(
      CloakFingerprintRequiredError,
    );
    await alice.session.acceptVault(trap.id);
    await alice.session.addMember(own.id, carol.userId, 'viewer');
  });

  it('cannot make a vault vouch with an acceptance of something else', async () => {
    const alice = await victim();
    const mallory = await victim();
    const dave = await victim();
    const carol = await victim();
    const own = await alice.session.createVault();
    const fromMallory = await mallory.session.createVault();
    await mallory.session.confirmFingerprint(alice.userId, alice.session.fingerprint);
    await alice.session.acceptInvitationsFrom(mallory.userId);
    await mallory.session.addMember(fromMallory.id, alice.userId, 'viewer');
    // Dave, whom Alice never accepted, adds her to a vault with Carol in it.
    const trap = await dave.session.createVault();
    await dave.session.confirmFingerprint(alice.userId, alice.session.fingerprint);
    await dave.session.confirmFingerprint(carol.userId, carol.session.fingerprint);
    await dave.session.addMember(trap.id, alice.userId, 'viewer');
    await dave.session.addMember(trap.id, carol.userId, 'viewer');
    const viewOf = async (vaultId: string) =>
      (await (
        await fetch(`${inject('cloakBaseUrl')}/vaults/${vaultId}`, {
          headers: { [USER_HEADER]: alice.userId },
        })
      ).json()) as Schemas['Vault'];
    const ownAcceptance = (await viewOf(own.id)).acceptance;
    const malloryAcceptance = (await viewOf(fromMallory.id)).acceptance;
    expect(ownAcceptance?.inviterUserId).toBeUndefined();
    expect(malloryAcceptance?.inviterUserId).toBe(mallory.cloakId);

    // Alice's real signatures, of her own vault and of Mallory, passed off as accepting the trap.
    for (const acceptance of [ownAcceptance, malloryAcceptance]) {
      const device = await anotherDevice(alice);
      device.hostile.rewrite = async (request, response) =>
        request.method === 'GET' && pathOf(request) === `/vaults/${trap.id}`
          ? json({ ...((await response.json()) as Schemas['Vault']), accepted: true, acceptance })
          : undefined;
      await device.session.openVault(trap.id);
      await expect(device.session.addMember(own.id, carol.userId, 'viewer')).rejects.toBeInstanceOf(
        CloakFingerprintRequiredError,
      );
    }
  });

  it('cannot get an unconfirmed person added by asking twice', async () => {
    const alice = await victim();
    const carol = await victim();
    const vault = await alice.session.createVault();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expect(
        alice.session.addMember(vault.id, carol.userId, 'viewer'),
      ).rejects.toBeInstanceOf(CloakFingerprintRequiredError);
    }
  });

  it('cannot hide what replaced keys signed from the key replacement', async () => {
    const alice = await victim();
    const bob = await victim();
    const carol = await victim();
    const dave = await victim();
    const vault = await alice.session.createVault();
    await meet(alice, bob);
    await alice.session.addMember(vault.id, bob.userId, 'admin');
    await meet(bob, dave);
    await bob.session.addMember(vault.id, dave.userId, 'viewer');

    // A thief holding Bob's old keys adds Carol; the server stores it.
    const thief = await anotherDevice(bob);
    await thief.session.confirmFingerprint(carol.userId, carol.session.fingerprint);
    const added = await thief.session.addMember(vault.id, carol.userId, 'viewer');

    const replaced = await replaceKeys(bob.client, {
      recoveryKeyCode: bob.recoveryKeyCode,
      newPassword: 'new',
    });
    expect(replaced.failedVaults).toEqual([]);
    expect(replaced.unrecognizedEntries).toEqual({ [vault.id]: [added.logSeq] });
  });

  it('cannot hide a vault from a batch read, or stall or stretch the change feed', async () => {
    const alice = await victim();
    const vaults = [await alice.session.createVault(), await alice.session.createVault()];
    const ids = vaults.map((vault) => vault.id);

    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'POST' || !pathOf(request).endsWith('/vaults/batch-get'))
        return undefined;
      const answer = (await response.json()) as Schemas['BatchGetVaultsResponse'];
      return json({ items: answer.items.slice(1) });
    };
    await expect(alice.session.openVaults(ids)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });

    const first = ids[0] ?? '';
    await alice.session.writeSection(
      first,
      await alice.session.createNode(first, 'record'),
      'general',
      {
        type: 'note',
        content: 'x',
      },
    );
    for (const forge of [
      (page: Schemas['SectionPage']) => ({ ...page, items: [], throughChangeSeq: 0 }),
      (page: Schemas['SectionPage']) => ({ ...page, throughChangeSeq: page.lastChangeSeq + 5 }),
    ]) {
      alice.hostile.rewrite = async (request, response) => {
        if (request.method !== 'GET' || !pathOf(request).endsWith('/sections')) return undefined;
        return json(forge((await response.json()) as Schemas['SectionPage']));
      };
      await expect(alice.session.readVault(ids[0] ?? '')).rejects.toMatchObject({
        reason: 'state_mismatch',
      });
    }
  });

  it('cannot collect several signed versions of a write by answering busy', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    const sent: string[] = [];
    alice.hostile.intercept = async (request) => {
      if (request.method !== 'PUT' || !pathOf(request).includes('/sections/')) return undefined;
      sent.push(await request.text());
      if (sent.length > 2) return undefined;
      return new Response(
        JSON.stringify({
          type: 'urn:cloak:problem:busy',
          code: 'busy',
          title: 'Busy',
          status: 503,
        }),
        {
          status: 503,
          headers: { 'content-type': 'application/problem+json', 'Retry-After': '1' },
        },
      );
    };

    await alice.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'once' });

    expect(sent).toHaveLength(3);
    expect(new Set(sent).size).toBe(1);
    const read = await alice.session.readSection(vault.id, nodeIdFor(node), 'general');
    expect(read).toMatchObject({ status: 'ok', dataVersion: 1 });
  });

  it('cannot pass off a leaf list that is not the signed checkpoint', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    for (let start = 0; start < 120; start += 60) {
      const batchNode = await alice.session.createNode(vault.id, `batch-${String(start)}`);
      await alice.session.writeSections(
        Array.from({ length: 60 }, (_, index) => ({
          vaultId: vault.id,
          node: batchNode,
          name: `item_${String(index)}`,
          type: 'server',
          content: 'listed',
        })),
      );
    }
    await alice.session.rotate(vault.id);

    const reader = await anotherDevice(alice);
    reader.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || !/\/checkpoints\/\d+\/leaves$/.test(pathOf(request)))
        return undefined;
      const page = (await response.json()) as Schemas['CheckpointLeafPage'];
      const [first, ...rest] = page.leaves;
      if (first === undefined) return undefined;
      return json({ ...page, leaves: [{ ...first, dataVersion: first.dataVersion + 1 }, ...rest] });
    };
    await expect(reader.session.changes(vault.id)).rejects.toMatchObject({
      name: 'CloakVaultLogError',
      reason: 'state_mismatch',
    });
  });

  it.each([
    [
      'cuts the list short',
      (page: Schemas['CheckpointLeafPage']) => ({
        checkpointSeq: page.checkpointSeq,
        size: page.size,
        leaves: page.leaves.slice(0, 10),
      }),
    ],
    [
      'cuts the list and its size',
      (page: Schemas['CheckpointLeafPage']) => ({
        checkpointSeq: page.checkpointSeq,
        size: 10,
        leaves: page.leaves.slice(0, 10),
      }),
    ],
    [
      'promises more pages forever',
      (page: Schemas['CheckpointLeafPage']) => ({
        checkpointSeq: page.checkpointSeq,
        size: page.size,
        leaves: [],
        nextCursor: 'again',
      }),
    ],
    [
      'claims more leaves than a vault has live sections, page after page',
      (page: Schemas['CheckpointLeafPage']) => ({
        checkpointSeq: page.checkpointSeq,
        size: 2_000_000_000,
        leaves: page.leaves,
        nextCursor: 'again',
      }),
    ],
  ])('cannot serve a checkpoint leaf list that %s', async (_, forge) => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const batchNode = await alice.session.createNode(vault.id, 'batch');
    await alice.session.writeSections(
      Array.from({ length: 100 }, (_, index) => ({
        vaultId: vault.id,
        node: batchNode,
        name: `item_${String(index)}`,
        type: 'server',
        content: 'listed',
      })),
    );
    await alice.session.rotate(vault.id);

    const reader = await anotherDevice(alice);
    reader.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || !/\/checkpoints\/\d+\/leaves$/.test(pathOf(request)))
        return undefined;
      return json(forge((await response.json()) as Schemas['CheckpointLeafPage']));
    };
    await expect(reader.session.changes(vault.id)).rejects.toMatchObject({
      name: 'CloakVaultLogError',
      reason: 'state_mismatch',
    });
  });

  it('cannot answer a proof with another section, or claim a held write absent', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSections([
      { vaultId: vault.id, node, name: 'general', type: 'server', content: 'a' },
      { vaultId: vault.id, node, name: 'secrets', type: 'server', content: 'b' },
    ]);
    await alice.session.rotate(vault.id);

    const swapped = await anotherDevice(alice);
    swapped.hostile.rewrite = async (request, response) => {
      if (request.method !== 'POST' || !pathOf(request).endsWith('/checkpoint-proofs/batch-get'))
        return undefined;
      const proofs = (await response.json()) as Schemas['BatchGetCheckpointProofsResponse'];
      return json({ items: [...proofs.items].reverse() });
    };
    await expect(swapped.session.readNode(nodeIdFor(node))).rejects.toMatchObject({
      reason: 'state_mismatch',
    });

    const hidden = await anotherDevice(alice);
    hidden.hostile.rewrite = async (request, response) => {
      if (request.method !== 'POST' || !pathOf(request).endsWith('/checkpoint-proofs/batch-get'))
        return undefined;
      const proofs = (await response.json()) as Schemas['BatchGetCheckpointProofsResponse'];
      return json({
        items: proofs.items.map((proof) => ({
          checkpointSeq: proof.checkpointSeq,
          size: proof.size,
        })),
      });
    };
    await expect(
      hidden.session.readSection(vault.id, nodeIdFor(node), 'general'),
    ).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
  });

  it('cannot serve a ciphertext other than the one the writer signed', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSections([
      { vaultId: vault.id, node, name: 'general', type: 'server', content: 'mine' },
      { vaultId: vault.id, node, name: 'secrets', type: 'server', content: 'other' },
    ]);
    const general = await storedWrite(alice.userId, vault.id, nodeIdFor(node), 'general');
    const secrets = await storedWrite(alice.userId, vault.id, nodeIdFor(node), 'secrets');
    const { ciphertext, ciphertextHash } = secrets;
    if (ciphertext === undefined || ciphertextHash === undefined) throw new Error('No content');

    const reader = await anotherDevice(alice);
    serveSection(reader.hostile, { ...general, ciphertext });
    expect(refusal(await reader.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'bad_ciphertext',
    );
    // The other ciphertext's hash, and the write hash it gives, under the signature of the first.
    const swapped = { ...general, ciphertext, ciphertextHash };
    serveSection(reader.hostile, {
      ...swapped,
      writeHash: toBase64Url(headerWriteHash(fromWireHeader(swapped))),
    });
    expect(refusal(await reader.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'bad_signature',
    );
  });

  it("cannot skip a new write's signature check by naming a write the device checked", async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSections([
      { vaultId: vault.id, node, name: 'general', type: 'server', content: 'kept' },
      { vaultId: vault.id, node, name: 'secrets', type: 'server', content: 'honest' },
    ]);
    const general = await storedWrite(alice.userId, vault.id, nodeIdFor(node), 'general');
    const secrets = await storedWrite(alice.userId, vault.id, nodeIdFor(node), 'secrets');

    const reader = await anotherDevice(alice);
    expect((await reader.session.readVault(vault.id)).sections).toHaveLength(2);

    // A deletion nobody signed, far ahead of the section's version, claiming the hash of a write
    // the reader already checked; then the same deletion with the hash it really has.
    const forged: Schemas['SectionWrite'] = {
      ...secrets,
      deleted: true,
      dataVersion: 2 ** 52,
      previousWriteHash: secrets.writeHash,
      signature: toBase64Url(Uint8Array.of(1, ...new Uint8Array(64))),
      writeHash: general.writeHash,
    };
    delete forged.ciphertext;
    delete forged.ciphertextHash;
    const honestHash = toBase64Url(headerWriteHash(fromWireHeader(forged)));
    const feedServing = (write: Schemas['SectionWrite']) => {
      reader.hostile.rewrite = async (request, response) => {
        if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}/sections`)
          return undefined;
        const page = (await response.json()) as Schemas['SectionPage'];
        return json({
          ...page,
          items: [...page.items, write],
          throughChangeSeq: write.changeSeq,
          lastChangeSeq: write.changeSeq,
        });
      };
    };
    const secretsIn = async () =>
      (await reader.session.readVault(vault.id)).sections.find(
        (section) => section.name === 'secrets',
      );

    feedServing({ ...forged, changeSeq: secrets.changeSeq + 100 });
    const copied = await secretsIn();
    expect(copied === undefined ? 'deleted' : refusal(copied)).toBe('bad_write_hash');
    feedServing({ ...forged, writeHash: honestHash, changeSeq: secrets.changeSeq + 200 });
    const own = await secretsIn();
    expect(own === undefined ? 'deleted' : refusal(own)).toBe('bad_signature');

    // Nothing the forgeries said reached the section's mark: the honest write still stands.
    reader.hostile.rewrite = undefined;
    const honest = await reader.session.readSection(vault.id, nodeIdFor(node), 'secrets');
    expect(honest.status).toBe('ok');
  });

  it('cannot make a device forget a vault by claiming a departure or deletion it never applied', async () => {
    const alice = await victim();
    const bob = await victim();
    await meet(alice, bob);
    const left = await alice.session.createVault();
    await alice.session.addMember(left.id, bob.userId, 'viewer');
    await bob.session.openVault(left.id);

    // The departure is answered but never stored: Bob is still a member by the real log.
    bob.hostile.intercept = (request) =>
      Promise.resolve(
        request.method === 'POST' && pathOf(request) === `/vaults/${left.id}/departures`
          ? new Response(null, { status: 204 })
          : undefined,
      );
    await bob.session.leave(left.id);
    bob.hostile.intercept = undefined;
    // The device kept its own signed departure as the head, so a log without it is refused.
    await expect(bob.session.openVault(left.id)).rejects.toMatchObject({ reason: 'rollback' });

    const deleted = await alice.session.createVault();
    alice.hostile.intercept = (request) =>
      Promise.resolve(
        request.method === 'POST' && pathOf(request) === `/vaults/${deleted.id}/deletion`
          ? new Response(null, { status: 204 })
          : undefined,
      );
    await expect(alice.session.deleteVault(deleted.id)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
    alice.hostile.intercept = undefined;
    expect((await alice.session.openVault(deleted.id)).deleted).toBe(false);
  });

  it('cannot lose an account by dropping the response to a registration or key replacement', async () => {
    const userId = crypto.randomUUID();
    const hostile: Hostile = {};
    const client = clientBehind(userId, hostile, createMemoryStorage());
    /**
     * Lets one request through to the real server, then fails as a dropped connection does; with
     * [identityToo], the read of the identity that follows fails the same way.
     */
    const dropResponse = (method: string, path: string, identityToo = false) => {
      let dropped = false;
      hostile.intercept = async (request) => {
        const isIdentityRead = request.method === 'GET' && pathOf(request) === '/identity';
        if (dropped && identityToo && isIdentityRead) {
          hostile.intercept = undefined;
          throw new TypeError('Network error');
        }
        if (dropped || request.method !== method || pathOf(request) !== path) return undefined;
        dropped = true;
        if (!identityToo) hostile.intercept = undefined;
        await fetch(request);
        throw new TypeError('Network error');
      };
    };
    const isNetworkError = (error: unknown) => isCloakApiError(error, 'network_error');

    // Applied, but answered with nothing: the server holds the prepared keys, so it is done.
    const registration = await client.prepareRegistration({ userId, password: 'password' });
    dropResponse('POST', '/identity');
    const session = await registration.complete();
    expect(await registration.complete()).toBe(session);
    const elsewhere = () => clientBehind(userId, {}, createMemoryStorage());
    expect(
      (
        await elsewhere().unlock({
          password: 'password',
          secretKeyCode: registration.secretKeyCode,
        })
      ).fingerprint,
    ).toBe(session.fingerprint);
    // Another registration of the same user is refused, and its keys are not taken for the ones held.
    const other = await client.prepareRegistration({ userId, password: 'other' });
    await expect(other.complete()).rejects.toSatisfy((error: unknown) =>
      isCloakApiError(error, 'already_exists'),
    );

    const replacement = await client.prepareKeyReplacement({
      recoveryKeyCode: registration.recoveryKeyCode,
      newPassword: 'new keys',
    });
    // Applied, and even the check that followed got nothing: called again, the request answers
    // `identity_version_conflict`, and the server holds the prepared keys, so it is done.
    dropResponse('PUT', '/identity/keys', true);
    await expect(replacement.complete()).rejects.toSatisfy(isNetworkError);
    const replaced = await replacement.complete();
    expect(replaced.session.keyVersion).toBe(2);
    const unlocked = await elsewhere().unlock({
      password: 'new keys',
      secretKeyCode: replacement.secretKeyCode,
    });
    expect(unlocked.keyVersion).toBe(2);
    await elsewhere().recover({
      recoveryKeyCode: replacement.recoveryKeyCode,
      newPassword: 'recovered',
    });
  });

  it('cannot tell a viewer, or keys the log does not commit, that a write succeeded', async () => {
    const alice = await victim();
    const bob = await victim();
    await meet(alice, bob);
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.addMember(vault.id, bob.userId, 'viewer');

    // The server would take the write and echo it as stored.
    let sent = 0;
    const acceptWrites = (hostile: Hostile, writerUserId: string) => {
      hostile.intercept = async (request) => {
        const match = /^\/vaults\/([^/]+)\/sections\/([^/]+)\/([^/]+)$/.exec(pathOf(request));
        if (request.method !== 'PUT' || match === null) return undefined;
        sent += 1;
        const [, vaultId = '', nodeId = '', sectionName = ''] = match;
        const input = (await request.json()) as Schemas['SectionWriteInput'];
        return json(served({ vaultId, nodeId, sectionName, input }, writerUserId));
      };
    };
    acceptWrites(bob.hostile, bob.cloakId);
    await expect(
      bob.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'viewer' }),
    ).rejects.toMatchObject({ name: 'CloakSectionError', reason: 'not_an_editor' });

    // An editor whose key replacement this vault never recorded still writes with old keys there.
    bob.hostile.intercept = undefined;
    await alice.session.setRole(vault.id, bob.userId, 'editor');
    bob.hostile.intercept = (request) =>
      Promise.resolve(
        request.method === 'POST' && pathOf(request) === `/vaults/${vault.id}/key-replacements`
          ? problem('internal_error', 500)
          : undefined,
      );
    const replaced = await replaceKeys(bob.client, {
      recoveryKeyCode: bob.recoveryKeyCode,
      newPassword: 'new keys',
    });
    expect(replaced.failedVaults).toEqual([vault.id]);
    acceptWrites(bob.hostile, bob.cloakId);
    await expect(
      replaced.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'v2' }),
    ).rejects.toMatchObject({ name: 'CloakSectionError', reason: 'not_an_editor' });
    expect(sent).toBe(0);
  });

  it('cannot make a writer chain to a version past what can be counted', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'one' });
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'POST' || pathOf(request) !== '/section-headers/batch-get')
        return undefined;
      const answer = (await response.json()) as Schemas['BatchGetSectionHeadersResponse'];
      return json({
        ...answer,
        items: answer.items.map((item) => ({ ...item, dataVersion: Number.MAX_SAFE_INTEGER })),
      });
    };
    await expect(
      alice.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'two' }),
    ).rejects.toMatchObject({ name: 'CloakVaultLogError', reason: 'state_mismatch' });
  });

  it('cannot make a node read hold more than one page, or page it forever', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    const nodeId = nodeIdFor(node);
    for (let start = 0; start < 10; start += 5) {
      await alice.session.writeSections(
        Array.from({ length: 5 }, (_, index) => ({
          vaultId: vault.id,
          node,
          name: `large_${String(start + index)}`,
          type: 'blob',
          content: 'x'.repeat(1_048_000),
        })),
      );
    }
    const nodePath = `/nodes/${nodeId}`;
    let pages = 0;

    // Every page at once, as a server that ignores the budget would send them.
    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'GET' || pathOf(request) !== nodePath) return undefined;
      let page = (await response.json()) as Schemas['NodeSections'];
      const sections = [...page.sections];
      while (page.nextCursor !== undefined) {
        const next = await fetch(
          `${inject('cloakBaseUrl')}${nodePath}?cursor=${encodeURIComponent(page.nextCursor)}`,
          { headers: request.headers },
        );
        page = (await next.json()) as Schemas['NodeSections'];
        sections.push(...page.sections);
      }
      return json({ nodeId, sections });
    };
    await expect(alice.session.readNode(nodeId)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });

    // A page that brings nothing but promises more.
    alice.hostile.rewrite = (request) =>
      Promise.resolve(
        request.method === 'GET' && pathOf(request) === nodePath
          ? json({ nodeId, sections: [], nextCursor: 'again' })
          : undefined,
      );
    await expect(alice.session.readNode(nodeId)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });

    // The first page again and again, with a cursor to yet another.
    alice.hostile.rewrite = async (request) => {
      if (request.method !== 'GET' || pathOf(request) !== nodePath) return undefined;
      pages += 1;
      const first = await fetch(`${inject('cloakBaseUrl')}${nodePath}`, {
        headers: request.headers,
      });
      return json({ ...((await first.json()) as Schemas['NodeSections']), nextCursor: 'again' });
    };
    await expect(alice.session.readNode(nodeId)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
    expect(pages).toBe(2);

    alice.hostile.rewrite = undefined;
    expect((await alice.session.readNode(nodeId)).sections).toHaveLength(10);
  });

  it('cannot keep a reader paging a log, a change feed or a vault list forever', async () => {
    const alice = await victim();
    const vault = await alice.session.createVault();
    const node = await alice.session.createNode(vault.id, 'record');
    await alice.session.writeSection(vault.id, node, 'general', { type: 'note', content: 'x' });
    const reader = await anotherDevice(alice);
    let pages = 0;

    // The first page of the log, again and again, with a head that is never reached.
    reader.hostile.rewrite = async (request) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}/log`)
        return undefined;
      pages += 1;
      const first = await fetch(`${inject('cloakBaseUrl')}/vaults/${vault.id}/log?limit=100`, {
        headers: request.headers,
      });
      const page = (await first.json()) as Schemas['VaultLogPage'];
      return json({ ...page, headSeq: 1_000_000 });
    };
    await expect(reader.session.openVault(vault.id)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
    expect(pages).toBe(2);

    // Pages that cover one more change each, bring nothing, and push the end further away.
    pages = 0;
    reader.hostile.rewrite = (request) => {
      if (request.method !== 'GET' || pathOf(request) !== `/vaults/${vault.id}/sections`)
        return Promise.resolve(undefined);
      pages += 1;
      const after = Number(new URL(request.url).searchParams.get('afterChange') ?? 0);
      return Promise.resolve(
        json({ items: [], removed: [], throughChangeSeq: after + 1, lastChangeSeq: after + 1000 }),
      );
    };
    await expect(reader.session.readVault(vault.id)).rejects.toMatchObject({
      reason: 'state_mismatch',
    });
    expect(pages).toBe(1);

    // The same vaults on every page, with a cursor to yet another.
    pages = 0;
    reader.hostile.rewrite = undefined;
    reader.hostile.intercept = async (request) => {
      if (request.method !== 'GET' || pathOf(request) !== '/vaults') return undefined;
      pages += 1;
      const first = await fetch(`${inject('cloakBaseUrl')}/vaults`, { headers: request.headers });
      return json({ ...((await first.json()) as Schemas['VaultPage']), nextCursor: 'again' });
    };
    await expect(reader.session.deleteAccount()).rejects.toSatisfy((error: unknown) =>
      isCloakApiError(error, 'unexpected_response'),
    );
    expect(pages).toBe(2);
    reader.hostile.intercept = undefined;
    expect((await reader.session.openVault(vault.id)).members).toHaveLength(1);
  });
});
