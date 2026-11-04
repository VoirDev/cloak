import { describe, expect, it } from 'vitest';

import { SMALL_ORDER_POINTS, checkSignature, isSmallOrderKey, sign } from '../src/index.ts';
import { identityNamed } from './fixtures.ts';
import { fromHex, hex, objects, text, toHex, vectors } from './vectors.ts';

const SIGNATURES = vectors('signatures.json');

describe('strict Ed25519', () => {
  it.each(objects(SIGNATURES, 'cases').map((vector) => [text(vector, 'name'), vector] as const))(
    'gives the vector verdict for %s',
    (_, vector) => {
      const reason = vector['reason'];
      expect(
        checkSignature(hex(vector, 'publicKey'), hex(vector, 'message'), hex(vector, 'signature')),
      ).toBe(reason === null ? undefined : reason);
    },
  );

  it('signs deterministically', () => {
    const valid = objects(SIGNATURES, 'cases').find((vector) => text(vector, 'name') === 'valid');
    if (valid === undefined) throw new Error('valid');
    expect(toHex(sign(identityNamed('owner-v1').signingSeed, hex(valid, 'message')))).toBe(
      text(valid, 'signature'),
    );
  });

  it('knows every small-order point', () => {
    expect(SMALL_ORDER_POINTS).toEqual(SIGNATURES['smallOrderPoints']);
    for (const point of SMALL_ORDER_POINTS) expect(isSmallOrderKey(fromHex(point))).toBe(true);
    expect(isSmallOrderKey(identityNamed('owner-v1').keys.signingPublicKey)).toBe(false);
  });

  it('refuses a malformed signature blob', () => {
    const key = identityNamed('owner-v1').keys.signingPublicKey;
    expect(checkSignature(key, new Uint8Array(1), new Uint8Array(64))).toBe('bad_signature');
    expect(checkSignature(key, new Uint8Array(1), new Uint8Array(65))).toBe('bad_signature');
  });
});
