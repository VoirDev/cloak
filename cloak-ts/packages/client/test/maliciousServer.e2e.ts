import {
  cloakUserId,
  createIdentity,
  entryHash,
  fromBase64Url,
  generateVaultKey,
  headerWriteHash,
  keysDigest,
  sealEnvelope,
  sectionCiphertextHash,
  signLogEntry,
  toBase64Url,
  type LogEntryFields,
} from '@voirdev/cloak-crypto';
import { describe, expect, inject, it } from 'vitest';

import {
  CloakFingerprintRequiredError,
  CloakKeyChangedError,
  createCloakClient,
  createMemoryStorage,
  nodeIdFor,
  type CloakClient,
  type CloakSession,
  type CloakStorage,
  type DecryptedSection,
} from '../src/index.ts';
import type { Schemas } from '../src/api.ts';
import { fromWireHeader } from '../src/wire.ts';

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
    ...(await client.register({ userId, password: 'password' })),
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
    writeHash: '',
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

/** The reason a section was refused. */
function refusal(section: DecryptedSection): string {
  return section.status === 'refused' ? section.reason : section.status;
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

    alice.hostile.rewrite = async (request, response) => {
      if (request.method !== 'POST' || pathOf(request) !== '/users/keys/batch-get')
        return undefined;
      const batch = (await response.json()) as Schemas['BatchGetUserKeysResponse'];
      return json({
        ...batch,
        items: batch.items.map((item) =>
          item.userId !== carol.cloakId
            ? item
            : {
                userId: carol.cloakId,
                hostUserId: carol.userId,
                versions: [
                  {
                    keys: {
                      userId: carol.cloakId,
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
      });
    };

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
    const replaced = await bob.client.replaceKeys({
      recoveryKeyCode: bob.recoveryKeyCode,
      newPassword: 'new',
    });
    bob.hostile.intercept = undefined;
    expect(replaced.failedVaults).toEqual([withheld.id]);

    // A thief with Bob's old keys writes in both vaults; the server serves what he signed.
    const inRecorded = captureNextWrite(oldKeys.hostile);
    await expect(
      oldKeys.session.writeSection(recorded.id, inRecordedNode, 'general', {
        type: 'server',
        content: 'thief',
      }),
    ).rejects.toThrow();
    const recordedWrite = served(await inRecorded, bob.cloakId);
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

    const replaced = await bob.client.replaceKeys({
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
    serveSection(reader.hostile, { ...general, ciphertext, ciphertextHash });
    expect(refusal(await reader.session.readSection(vault.id, nodeIdFor(node), 'general'))).toBe(
      'bad_signature',
    );
  });
});
