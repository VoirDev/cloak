import { describe, expect, it } from 'vitest';

import {
  CloakCryptoError,
  contentKey,
  deriveLocalRecordKey,
  deriveMasterKey,
  derivePasswordKey,
  deriveRecoverySigningKey,
  keyCommitment,
  privateKeyBundleKey,
  recoveryBundleKey,
  requireCommittedKey,
  requireKdfParams,
  secretKeyMaterial,
  wrapKey,
} from '../src/index.ts';
import { child, hex, num, objects, text, toHex, vectors } from './vectors.ts';

const KDF = vectors('kdf.json');

describe('key derivation', () => {
  it('derives the master key from the NFKC password and the secret key', async () => {
    const vector = child(KDF, 'masterKey');
    const kdf = child(vector, 'kdf');
    const userId = text(vector, 'userId');

    const masterKey = await deriveMasterKey({
      password: text(vector, 'password'),
      secretKey: hex(vector, 'secretKey'),
      userId,
      kdf: {
        salt: hex(kdf, 'salt'),
        memoryKib: num(kdf, 'memoryKib'),
        iterations: num(kdf, 'iterations'),
        parallelism: 1,
      },
    });

    expect(toHex(secretKeyMaterial(hex(vector, 'secretKey'), userId))).toBe(
      text(vector, 'secretKeyMaterial'),
    );
    expect(toHex(masterKey)).toBe(text(vector, 'masterKey'));
    expect(toHex(privateKeyBundleKey(masterKey))).toBe(text(vector, 'privateKeyBundleKey'));
  });

  it('runs Argon2id wherever the caller says, and refuses a password key of the wrong size', async () => {
    const vector = child(KDF, 'masterKey');
    const kdf = child(vector, 'kdf');
    const options = {
      password: text(vector, 'password'),
      secretKey: hex(vector, 'secretKey'),
      userId: text(vector, 'userId'),
      kdf: {
        salt: hex(kdf, 'salt'),
        memoryKib: num(kdf, 'memoryKib'),
        iterations: num(kdf, 'iterations'),
        parallelism: 1,
      },
    };
    const asked: string[] = [];
    const masterKey = await deriveMasterKey({
      ...options,
      passwordHasher: (password, params) => {
        asked.push(password);
        return derivePasswordKey(password, params);
      },
    });

    expect(asked).toEqual([options.password]);
    expect(toHex(masterKey)).toBe(text(vector, 'masterKey'));
    await expect(
      deriveMasterKey({ ...options, passwordHasher: () => Promise.resolve(new Uint8Array(16)) }),
    ).rejects.toMatchObject({ code: 'invalid_format' });
  });

  it('accepts KDF parameters within the bounds and refuses the others', () => {
    const limits = child(KDF, 'kdfLimits');
    const params = (json: ReturnType<typeof child>) => ({
      salt: new Uint8Array(16),
      memoryKib: num(json, 'memoryKib'),
      iterations: num(json, 'iterations'),
      parallelism: 1 as const,
    });
    for (const accepted of objects(limits, 'accept')) {
      expect(() => {
        requireKdfParams(params(accepted));
      }).not.toThrow();
    }
    for (const refused of objects(limits, 'refuse')) {
      expect(() => {
        requireKdfParams(params(refused));
      }).toThrow(new CloakCryptoError('invalid_kdf', 'KDF parameters are out of bounds'));
    }
  });

  it('derives the recovery bundle key and recovery signing key', () => {
    for (const vector of objects(KDF, 'recoveryKeys')) {
      const userId = text(vector, 'userId');
      const recoveryKey = hex(vector, 'recoveryKey');
      const signing = deriveRecoverySigningKey(recoveryKey, userId);
      expect(toHex(recoveryBundleKey(recoveryKey, userId))).toBe(
        text(vector, 'recoveryKeyBundleKey'),
      );
      expect(toHex(signing.seed)).toBe(text(vector, 'recoverySigningSeed'));
      expect(toHex(signing.publicKey)).toBe(text(vector, 'recoverySigningPublicKey'));
    }
  });

  it('derives the content key, wrapping key and commitment of each vault key', () => {
    for (const vector of objects(KDF, 'vaultKeys')) {
      const vaultId = text(vector, 'vaultId');
      const key = hex(vector, 'vaultKey');
      const version = num(vector, 'keyVersion');
      expect(toHex(contentKey(key, vaultId))).toBe(text(vector, 'contentKey'));
      expect(toHex(wrapKey(key, vaultId))).toBe(text(vector, 'wrapKey'));
      expect(toHex(keyCommitment(key, vaultId, version))).toBe(text(vector, 'keyCommitment'));
      expect(requireCommittedKey(key, vaultId, version, hex(vector, 'keyCommitment'))).toBe(key);
    }
  });

  it('refuses a vault key that is not the committed one', () => {
    const vector = child(KDF, 'keyMismatch');
    const vaultId = text(vector, 'vaultId');
    const version = num(vector, 'keyVersion');
    const opened = hex(vector, 'openedKey');
    expect(toHex(keyCommitment(opened, vaultId, version))).toBe(text(vector, 'itsCommitment'));
    expect(() => requireCommittedKey(opened, vaultId, version, hex(vector, 'committed'))).toThrow(
      expect.objectContaining({ code: text(vector, 'reason') }),
    );
  });

  it('derives the local record key from the local state key', () => {
    for (const vector of objects(KDF, 'localState')) {
      expect(
        toHex(deriveLocalRecordKey(hex(vector, 'localStateKey'), text(vector, 'userId'))),
      ).toBe(text(vector, 'recordKey'));
    }
  });
});
