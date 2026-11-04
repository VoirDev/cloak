import { describe, expect, it } from 'vitest';

import {
  fingerprint,
  fingerprintMessage,
  fromCrockford,
  fromRecoveryKeyCode,
  fromSecretKeyCode,
  isCloakCryptoError,
  keysDigest,
  toCrockford,
  toRecoveryKeyCode,
  toSecretKeyCode,
} from '../src/index.ts';
import { toIdentity } from './fixtures.ts';
import { child, fromHex, hex, objects, text, toHex, vectors } from './vectors.ts';

const TEXT = vectors('text.json');

describe('human-readable codes', () => {
  it('encodes and decodes Crockford base32', () => {
    for (const vector of objects(TEXT, 'crockford')) {
      const bytes = fromHex(text(vector, 'input'));
      expect(toCrockford(bytes)).toBe(text(vector, 'expected'));
      expect(toHex(fromCrockford(text(vector, 'expected'), bytes.length))).toBe(
        text(vector, 'input'),
      );
    }
  });

  it('formats and parses the secret key code, in any case', () => {
    const vector = child(TEXT, 'secretKey');
    expect(toSecretKeyCode(hex(vector, 'bytes'))).toBe(text(vector, 'code'));
    expect(toHex(fromSecretKeyCode(text(vector, 'code')))).toBe(text(vector, 'bytes'));
    expect(toHex(fromSecretKeyCode(text(vector, 'lowercase')))).toBe(text(vector, 'bytes'));
  });

  it('formats and parses the recovery key code', () => {
    const vector = child(TEXT, 'recoveryKey');
    expect(toRecoveryKeyCode(hex(vector, 'bytes'))).toBe(text(vector, 'code'));
    expect(toHex(fromRecoveryKeyCode(text(vector, 'code')))).toBe(text(vector, 'bytes'));
  });

  it('computes the fingerprint of a key version', () => {
    const vector = child(TEXT, 'fingerprint');
    const keys = toIdentity(child(vector, 'identity')).keys;
    expect(toHex(fingerprintMessage(keys))).toBe(text(vector, 'message'));
    expect(toHex(keysDigest(keys))).toBe(text(vector, 'digest'));
    expect(fingerprint(keys)).toBe(text(vector, 'code'));
  });

  it.each(objects(TEXT, 'negatives').map((vector) => [text(vector, 'name'), vector] as const))(
    'refuses %s',
    (_, vector) => {
      const parse = text(vector, 'kind') === 'secretKey' ? fromSecretKeyCode : fromRecoveryKeyCode;
      let code: string | undefined;
      try {
        parse(text(vector, 'code'));
      } catch (error: unknown) {
        if (isCloakCryptoError(error)) code = error.code;
      }
      expect(code).toBe(text(vector, 'reason'));
    },
  );
});
