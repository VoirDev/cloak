import { cloakUserId, createIdentity, toBase64Url } from '@voirdev/cloak-crypto';
import { describe, expect, it } from 'vitest';

import { createCloakClient } from '../src/client.ts';
import { createMemoryStorage, type CloakStorage } from '../src/storage/CloakStorage.ts';
import { secretKeyRecord } from '../src/storage/localState.ts';
import { toWireKdf } from '../src/wire.ts';

describe('the client', () => {
  it('overwrites the secret key it read once a session is unlocked', async () => {
    const userId = cloakUserId('alice');
    const identity = await createIdentity(userId, 'password');
    const fetchIdentity = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      expect(new URL(new Request(input, init).url).pathname).toBe('/cloak/v1/identity');
      const { keys } = identity;
      return Promise.resolve(
        new Response(
          JSON.stringify({
            hostUserId: 'alice',
            keys: {
              userId,
              keyVersion: keys.keyVersion,
              cryptoSuite: keys.cryptoSuite,
              encryptionPublicKey: toBase64Url(keys.encryptionPublicKey),
              signingPublicKey: toBase64Url(keys.signingPublicKey),
              recoverySigningPublicKey: toBase64Url(keys.recoverySigningPublicKey),
            },
            kdf: toWireKdf(identity.kdf),
            privateKeyBundle: toBase64Url(identity.privateKeyBundle),
            recoveryKeyBundle: toBase64Url(identity.recoveryKeyBundle),
            credentialsVersion: 1,
            createdAt: '2026-11-26T00:00:00Z',
            updatedAt: '2026-11-26T00:00:00Z',
          }),
          { headers: { 'content-type': 'application/json' } },
        ),
      );
    };
    // A store that hands out the remembered secret key itself, so the test sees what is done to it.
    const memory = createMemoryStorage();
    await memory.set(secretKeyRecord(userId), identity.secretKey);
    const handedOut: Uint8Array[] = [];
    const storage: CloakStorage = {
      ...memory,
      get: async (key) => {
        const value = await memory.get(key);
        if (value !== undefined && key === secretKeyRecord(userId)) handedOut.push(value);
        return value;
      },
    };

    const client = createCloakClient({
      baseUrl: 'http://cloak.test/cloak/v1',
      storage,
      fetch: fetchIdentity,
    });
    await client.unlock({ password: 'password' });
    await expect(client.unlock({ password: 'wrong' })).rejects.toMatchObject({
      reason: 'wrong_credentials',
    });

    expect(handedOut).toHaveLength(2);
    for (const secretKey of handedOut) expect(secretKey).toEqual(new Uint8Array(16));
  }, 60_000);
});
