import {
  cloakUserId,
  createIdentity,
  fingerprint,
  openRecoveryKeyBundle,
  replaceIdentityKeys,
  toBase64Url,
  type KeyStatement,
  type NewKeyVersion,
} from '@voirdev/cloak-crypto';
import { beforeAll, describe, expect, it } from 'vitest';

import { CloakKeyChangedError } from '../src/CloakKeyChangedError.ts';
import { createApi } from '../src/api.ts';
import { createKeyring } from '../src/keyring.ts';
import { createMemoryStorage } from '../src/storage/CloakStorage.ts';
import { openLocalState } from '../src/storage/localState.ts';

const ALICE = cloakUserId('alice');
const BOB = cloakUserId('bob@example.com');

/** Wire form of a statement. */
function wire(statement: KeyStatement) {
  const { keys } = statement;
  return {
    keys: {
      userId: keys.userId,
      keyVersion: keys.keyVersion,
      cryptoSuite: keys.cryptoSuite,
      encryptionPublicKey: toBase64Url(keys.encryptionPublicKey),
      signingPublicKey: toBase64Url(keys.signingPublicKey),
      recoverySigningPublicKey: toBase64Url(keys.recoverySigningPublicKey),
    },
    signature: toBase64Url(statement.signature),
    ...(statement.recoverySignature === undefined
      ? {}
      : { recoverySignature: toBase64Url(statement.recoverySignature) }),
  };
}

/**
 * A keyring for Alice over a server that serves [served] for Bob, named [bobHostId] (`null` sends
 * no name) and marked deleted when [bobDeleted].
 */
function keyringServing(
  alice: NewKeyVersion,
  served: () => readonly KeyStatement[],
  storage = createMemoryStorage(),
  bobHostId: string | null = 'bob@example.com',
  bobDeleted = false,
) {
  const api = createApi({
    baseUrl: 'http://cloak.test/cloak/v1',
    fetch: (input, init) => {
      const request = new Request(input, init);
      const bodyJson = {
        items: [
          {
            userId: BOB,
            ...(bobHostId === null ? {} : { hostUserId: bobHostId }),
            deleted: bobDeleted,
            versions: served().map(wire),
          },
          { userId: ALICE, hostUserId: 'alice', deleted: false, versions: [wire(alice.statement)] },
        ],
        missingUserIds: [],
      };
      expect(new URL(request.url).pathname).toBe('/cloak/v1/users/keys/batch-get');
      return Promise.resolve(
        new Response(JSON.stringify(bodyJson), { headers: { 'content-type': 'application/json' } }),
      );
    },
  });
  const local = openLocalState(storage, ALICE, alice.secrets.localStateKey);
  return { keyring: createKeyring(api, local, alice.keys, 'alice'), local };
}

describe('the keyring', () => {
  let alice: NewKeyVersion;
  let bob: NewKeyVersion;
  let bobV2: NewKeyVersion;

  beforeAll(async () => {
    alice = await createIdentity(ALICE, 'alice password');
    bob = await createIdentity(BOB, 'bob password');
    const secrets = openRecoveryKeyBundle(bob.recoveryKey, bob.keys, bob.recoveryKeyBundle);
    bobV2 = await replaceIdentityKeys({
      current: bob.keys,
      currentSecrets: secrets,
      currentRecoveryKey: bob.recoveryKey,
      password: 'new',
    });
  }, 60_000);

  it('pins a person at their first version and follows their statements', async () => {
    const { keyring, local } = keyringServing(alice, () => [bob.statement, bobV2.statement]);

    await keyring.load([BOB]);

    expect((await local.pin(BOB))?.keyVersion).toBe(1);
    expect(keyring.newest(BOB)).toEqual(bobV2.keys);
    expect(keyring.isSuperseded(BOB, 1)).toBe(true);
    expect(keyring.isSuperseded(BOB, 2)).toBe(false);
    expect(keyring.hostIdOf(BOB)).toBe('bob@example.com');
  });

  it('refuses a host user id that does not derive the person it names', async () => {
    const { keyring } = keyringServing(
      alice,
      () => [bob.statement],
      createMemoryStorage(),
      'mallory@example.com',
    );
    await expect(keyring.load([BOB])).rejects.toMatchObject({
      name: 'CloakApiError',
      code: 'unexpected_response',
    });
    expect(keyring.hostIdOf(BOB)).toBeUndefined();
  });

  it('keeps showing a deleted person by the host user id it checked before', async () => {
    const storage = createMemoryStorage();
    await keyringServing(alice, () => [bob.statement], storage).keyring.load([BOB]);

    const { keyring } = keyringServing(alice, () => [bob.statement], storage, null, true);
    await keyring.load([BOB]);

    expect(keyring.hostIdOf(BOB)).toBe('bob@example.com');
    expect(keyring.isDeleted(BOB)).toBe(true);
    expect(keyring.newest(BOB)?.keyVersion).toBe(1);
  });

  it('knows a deleted person it never met only by their id', async () => {
    const { keyring } = keyringServing(
      alice,
      () => [bob.statement],
      createMemoryStorage(),
      null,
      true,
    );
    await keyring.load([BOB]);

    expect(keyring.hostIdOf(BOB)).toBeUndefined();
    expect(keyring.isDeleted(BOB)).toBe(true);
  });

  it('refuses a person who is not deleted but comes without a host user id', async () => {
    const { keyring } = keyringServing(alice, () => [bob.statement], createMemoryStorage(), null);
    await expect(keyring.load([BOB])).rejects.toMatchObject({
      name: 'CloakApiError',
      code: 'unexpected_response',
    });
  });

  it('still refuses a host user id of someone else for a deleted person', async () => {
    const { keyring } = keyringServing(
      alice,
      () => [bob.statement],
      createMemoryStorage(),
      'mallory@example.com',
      true,
    );
    await expect(keyring.load([BOB])).rejects.toMatchObject({ code: 'unexpected_response' });
  });

  it('raises a key alarm when the server swaps a pinned version', async () => {
    const storage = createMemoryStorage();
    let served: readonly KeyStatement[] = [bob.statement];
    const first = keyringServing(alice, () => served, storage);
    await first.keyring.load([BOB]);

    const impostor = await createIdentity(BOB, 'server password');
    served = [impostor.statement];
    const second = keyringServing(alice, () => served, storage);
    await expect(second.keyring.load([BOB])).rejects.toBeInstanceOf(CloakKeyChangedError);
  });

  it('refuses a next version the previous recovery key did not sign', async () => {
    const forged = { ...bobV2.statement, recoverySignature: bobV2.statement.signature };
    const { keyring } = keyringServing(alice, () => [bob.statement, forged]);

    await expect(keyring.load([BOB])).rejects.toMatchObject({
      name: 'CloakKeyChangedError',
      keyVersion: 2,
    });
  });

  it('pins the first version when a later confirmed fingerprint is on its chain', async () => {
    const { keyring, local } = keyringServing(alice, () => [bob.statement, bobV2.statement]);

    await expect(keyring.confirm(BOB, 'AAAA-BBBB')).rejects.toBeInstanceOf(CloakKeyChangedError);
    expect(await local.pin(BOB)).toBeUndefined();
    await keyring.confirm(BOB, fingerprint(bobV2.keys).toLowerCase());

    expect((await local.pin(BOB))?.keyVersion).toBe(1);
    expect(keyring.newest(BOB)?.keyVersion).toBe(2);
  });

  it('raises a key alarm when a confirmed fingerprint is off the pinned chain', async () => {
    const storage = createMemoryStorage();
    const first = keyringServing(alice, () => [bob.statement], storage);
    await first.keyring.load([BOB]);

    const impostor = await createIdentity(BOB, 'server password');
    const second = keyringServing(alice, () => [bob.statement], storage);
    await expect(second.keyring.confirm(BOB, fingerprint(impostor.keys))).rejects.toBeInstanceOf(
      CloakKeyChangedError,
    );
  });

  it('raises a key alarm when the server later hides newer statements', async () => {
    const storage = createMemoryStorage();
    const first = keyringServing(alice, () => [bob.statement, bobV2.statement], storage);
    await first.keyring.load([BOB]);

    const second = keyringServing(alice, () => [bob.statement], storage);
    await expect(second.keyring.load([BOB])).rejects.toBeInstanceOf(CloakKeyChangedError);
  });
});
