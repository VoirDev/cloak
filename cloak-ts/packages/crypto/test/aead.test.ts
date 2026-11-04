import { describe, expect, it } from 'vitest';

import { decryptBlob, encryptBlob } from '../src/blobs.ts';
import {
  decryptSection,
  encryptSection,
  isCloakCryptoError,
  openLocalRecord,
  openPrivateKeyBundle,
  openRecoveryKeyBundle,
  pad,
  sealLocalRecord,
  sealPrivateKeyBundle,
  sealRecoveryKeyBundle,
  unpad,
  unwrapPreviousKey,
  wrapPreviousKey,
  nodeIdOf,
} from '../src/index.ts';
import { identityNamed } from './fixtures.ts';
import { child, fromHex, hex, objects, text, toHex, utf8Of, vectors } from './vectors.ts';

const AEAD = vectors('aead.json');
const KDF = vectors('kdf.json');
const CASES = objects(AEAD, 'cases');
const OWNER = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e';
const VAULT = '0192f5a3-0000-7aaa-8bbb-0123456789ab';
/** The scenario's node: owned by the owner, homed in the vault, keyed `server-1`. */
const NODE = nodeIdOf({ ownerUserId: OWNER, homeVaultId: VAULT, nodeKey: 'server-1' });
const LOCAL_STATE_KEYS = objects(KDF, 'localState').map((vector) => hex(vector, 'localStateKey'));
const VAULT_KEYS = objects(KDF, 'vaultKeys').map((vector) => hex(vector, 'vaultKey'));

/** A named case of aead.json. */
function aeadCase(name: string): ReturnType<typeof child> {
  const found = CASES.find((vector) => text(vector, 'name') === name);
  if (found === undefined) throw new Error(name);
  return found;
}

/** The code a call throws, if any. */
function errorCode(call: () => unknown): string | undefined {
  try {
    call();
  } catch (error: unknown) {
    if (isCloakCryptoError(error)) return error.code;
    throw error;
  }
  return undefined;
}

describe('encrypted blobs', () => {
  it.each(CASES.map((vector) => [text(vector, 'name'), vector] as const))(
    'encrypts and decrypts %s',
    (_, vector) => {
      const blob = encryptBlob(
        hex(vector, 'key'),
        hex(vector, 'ad'),
        hex(vector, 'plaintext'),
        hex(vector, 'nonce'),
      );
      expect(toHex(blob)).toBe(text(vector, 'blob'));
      expect(toHex(decryptBlob(hex(vector, 'key'), hex(vector, 'ad'), blob))).toBe(
        text(vector, 'plaintext'),
      );
    },
  );

  it('seals and opens the private key bundles of versions 1 and 2', () => {
    const masterBundleKey = child(KDF, 'masterKey');
    const masterKey = hex(masterBundleKey, 'masterKey');
    const ownerV1 = identityNamed('owner-v1');
    const ownerV2 = identityNamed('owner-v2');
    const v1 = {
      encryptionPrivateKey: ownerV1.encryptionPrivateKey,
      signingSeed: ownerV1.signingSeed,
      localStateKey: LOCAL_STATE_KEYS[0] ?? new Uint8Array(),
      earlierEncryptionKeys: [],
    };
    const v2 = {
      encryptionPrivateKey: ownerV2.encryptionPrivateKey,
      signingSeed: ownerV2.signingSeed,
      localStateKey: LOCAL_STATE_KEYS[1] ?? new Uint8Array(),
      previousLocalStateKey: LOCAL_STATE_KEYS[0],
      earlierEncryptionKeys: [ownerV1.encryptionPrivateKey],
    };

    const first = aeadCase('private-key-bundle-v1');
    const second = aeadCase('private-key-bundle-v2');
    expect(toHex(sealPrivateKeyBundle(masterKey, ownerV1.keys, v1, hex(first, 'nonce')))).toBe(
      text(first, 'blob'),
    );
    expect(toHex(sealPrivateKeyBundle(masterKey, ownerV2.keys, v2, hex(second, 'nonce')))).toBe(
      text(second, 'blob'),
    );
    expect(openPrivateKeyBundle(masterKey, ownerV2.keys, hex(second, 'blob'))).toEqual(v2);
    expect(openPrivateKeyBundle(masterKey, ownerV1.keys, hex(first, 'blob'))).toEqual({
      ...v1,
      previousLocalStateKey: undefined,
    });
    expect(
      errorCode(() => openPrivateKeyBundle(masterKey, ownerV1.keys, hex(second, 'blob'))),
    ).toBe('decryption_failed');

    const recovery = aeadCase('recovery-key-bundle-v1');
    expect(
      toHex(sealRecoveryKeyBundle(ownerV1.recoveryKey, ownerV1.keys, v1, hex(recovery, 'nonce'))),
    ).toBe(text(recovery, 'blob'));
    expect(openRecoveryKeyBundle(ownerV1.recoveryKey, ownerV1.keys, hex(recovery, 'blob'))).toEqual(
      { ...v1, previousLocalStateKey: undefined },
    );
  });

  it('encrypts section content with the vault content key', () => {
    const vector = aeadCase('section-content');
    const address = { vaultId: VAULT, nodeId: NODE, sectionName: 'general', vaultKeyVersion: 1 };
    const vaultKey = VAULT_KEYS[0] ?? new Uint8Array();
    const content = utf8Of(text(vector, 'contentUtf8'));
    expect(toHex(encryptSection(vaultKey, address, content, hex(vector, 'nonce')))).toBe(
      text(vector, 'blob'),
    );
    expect(toHex(decryptSection(vaultKey, address, hex(vector, 'blob')))).toBe(toHex(content));
    expect(
      errorCode(() =>
        decryptSection(vaultKey, { ...address, vaultKeyVersion: 2 }, hex(vector, 'blob')),
      ),
    ).toBe('decryption_failed');
  });

  it('wraps the previous vault key by the next one', () => {
    const vector = aeadCase('vault-previous');
    const [v1, v2] = VAULT_KEYS;
    if (v1 === undefined || v2 === undefined) throw new Error('vault keys');
    expect(toHex(wrapPreviousKey(v2, VAULT, 2, v1, hex(vector, 'nonce')))).toBe(
      text(vector, 'blob'),
    );
    expect(toHex(unwrapPreviousKey(v2, VAULT, 2, hex(vector, 'blob')))).toBe(toHex(v1));
    expect(errorCode(() => unwrapPreviousKey(v2, VAULT, 3, hex(vector, 'blob')))).toBe(
      'decryption_failed',
    );
  });

  it('seals a local record under its name', () => {
    const vector = aeadCase('local-record');
    const name = `cloak/v1/${OWNER}/pins`;
    expect(
      toHex(
        sealLocalRecord(hex(vector, 'key'), name, hex(vector, 'plaintext'), hex(vector, 'nonce')),
      ),
    ).toBe(text(vector, 'blob'));
    expect(
      errorCode(() => openLocalRecord(hex(vector, 'key'), `${name}x`, hex(vector, 'blob'))),
    ).toBe('decryption_failed');
  });

  it('refuses a blob opened with the wrong associated data', () => {
    for (const vector of objects(AEAD, 'negatives')) {
      expect(
        errorCode(() => decryptBlob(hex(vector, 'key'), hex(vector, 'ad'), hex(vector, 'blob'))),
      ).toBe(text(vector, 'reason'));
    }
  });
});

describe('padding', () => {
  it('pads to whole 256-byte blocks and back', () => {
    for (const vector of objects(AEAD, 'padding')) {
      expect(toHex(pad(hex(vector, 'input')))).toBe(text(vector, 'padded'));
      expect(toHex(unpad(hex(vector, 'padded')))).toBe(text(vector, 'input'));
    }
  });

  it.each(
    objects(AEAD, 'paddingNegatives').map((vector) => [text(vector, 'name'), vector] as const),
  )('refuses %s', (_, vector) => {
    expect(errorCode(() => unpad(fromHex(text(vector, 'input'))))).toBe(text(vector, 'reason'));
  });
});
