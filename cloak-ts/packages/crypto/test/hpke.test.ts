import { describe, expect, it } from 'vitest';

import { openBlob, sealBlob } from '../src/hpke.ts';
import { ENVELOPE_BYTES, isCloakCryptoError, openEnvelope, sealEnvelope } from '../src/index.ts';
import { identityNamed } from './fixtures.ts';
import { hex, objects, text, toHex, vectors } from './vectors.ts';

const HPKE = vectors('hpke.json');
const CASES = objects(HPKE, 'cases');
const VAULT = '0192f5a3-0000-7aaa-8bbb-0123456789ab';

describe('envelopes', () => {
  it.each(CASES.map((vector) => [text(vector, 'name'), vector] as const))(
    'seals %s with the vector ephemeral key and opens it',
    async (_, vector) => {
      const sealed = await sealBlob(
        hex(vector, 'pkR'),
        hex(vector, 'info'),
        hex(vector, 'aad'),
        hex(vector, 'plaintext'),
        hex(vector, 'ikmE'),
      );
      expect(toHex(sealed)).toBe(text(vector, 'blob'));
      expect(
        toHex(await openBlob(hex(vector, 'skR'), hex(vector, 'info'), hex(vector, 'aad'), sealed)),
      ).toBe(text(vector, 'plaintext'));
    },
  );

  it.each(CASES.map((vector) => [text(vector, 'name'), vector] as const))(
    'builds the envelope of %s from the vault and recipient',
    async (_, vector) => {
      const recipient = identityNamed(text(vector, 'recipient'));
      const keyVersion = Number(/vault-key-v(\d)/.exec(text(vector, 'name'))?.[1]);
      const to = { userId: recipient.keys.userId, userKeyVersion: recipient.keys.keyVersion };

      const envelope = await sealEnvelope(
        recipient.keys.encryptionPublicKey,
        VAULT,
        keyVersion,
        to,
        hex(vector, 'plaintext'),
        hex(vector, 'ikmE'),
      );

      expect(toHex(envelope)).toBe(text(vector, 'blob'));
      expect(
        toHex(await openEnvelope(recipient.encryptionPrivateKey, VAULT, keyVersion, to, envelope)),
      ).toBe(text(vector, 'plaintext'));
      expect(envelope.length).toBe(ENVELOPE_BYTES);
    },
  );

  it('refuses an envelope opened for another member key version', async () => {
    for (const vector of objects(HPKE, 'negatives')) {
      let code: string | undefined;
      try {
        await openBlob(
          hex(vector, 'skR'),
          hex(vector, 'info'),
          hex(vector, 'aad'),
          hex(vector, 'blob'),
        );
      } catch (error: unknown) {
        if (isCloakCryptoError(error)) code = error.code;
      }
      expect(code).toBe(text(vector, 'reason'));
    }
  });
});
