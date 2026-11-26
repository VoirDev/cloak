import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { BLOB_FORMAT, ENC_BYTES, requireFormat } from './blobs.ts';
import { concatBytes } from './bytes.ts';
import type { KeyRefusal } from './signatures.ts';

/** The X25519 field prime. */
const FIELD_PRIME = 2n ** 255n - 19n;

/**
 * u-coordinates of the five X25519 points of small order, little-endian hex: 0, 1, p − 1, and the
 * two points of order 8 (`PROTOCOL.md` §5.1).
 */
const SMALL_ORDER_U: readonly string[] = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
];

/**
 * Checks an X25519 public key as clients and the server do before anyone seals to it
 * (`PROTOCOL.md` §5.1): 32 bytes, top bit clear, below the field prime, and not of small order,
 * so sealing a vault key to a member never fails or yields a secret everyone knows.
 *
 * @param publicKey Raw X25519 public key.
 * @returns `undefined` when usable, otherwise why it is refused.
 */
export function checkEncryptionKey(publicKey: Uint8Array): KeyRefusal | undefined {
  if (publicKey.length !== 32 || ((publicKey[31] ?? 0) & 0x80) !== 0) return 'non_canonical_key';
  let u = 0n;
  for (let index = 31; index >= 0; index -= 1) u = (u << 8n) | BigInt(publicKey[index] ?? 0);
  if (u >= FIELD_PRIME) return 'non_canonical_key';
  const encoded = Array.from(publicKey, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return SMALL_ORDER_U.includes(encoded) ? 'small_order_key' : undefined;
}

/** HPKE suite 1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (RFC 9180). */
const SUITE = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

/** Size of a ChaCha20-Poly1305 tag. */
const TAG_BYTES = 16;

/**
 * Seals into a sealed blob: `0x01 ‖ enc (32) ‖ ciphertext ‖ tag (16)`, single-shot HPKE base mode.
 *
 * @param recipientPublicKey Raw 32-byte X25519 public key.
 * @param info HPKE info.
 * @param aad Associated data.
 * @param plaintext Bytes to seal.
 * @param ephemeralIkm Input keying material of the ephemeral key; random unless a test fixes it.
 * @returns The sealed blob.
 */
export async function sealBlob(
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  ephemeralIkm?: Uint8Array,
): Promise<Uint8Array> {
  const refusal = checkEncryptionKey(recipientPublicKey);
  if (refusal !== undefined)
    throw new CloakCryptoError('invalid_format', `Cannot seal to this X25519 key: ${refusal}`);
  let sealed;
  try {
    sealed = await SUITE.seal(
      {
        recipientPublicKey: await SUITE.kem.deserializePublicKey(recipientPublicKey),
        info,
        ...(ephemeralIkm === undefined ? {} : { ekm: ephemeralIkm }),
      },
      plaintext,
      aad,
    );
  } catch (error: unknown) {
    throw new CloakCryptoError('invalid_format', 'Sealing failed', { cause: error });
  }
  return concatBytes(
    Uint8Array.of(BLOB_FORMAT),
    new Uint8Array(sealed.enc),
    new Uint8Array(sealed.ct),
  );
}

/**
 * Opens a sealed blob.
 *
 * @param recipientPrivateKey Raw 32-byte X25519 private key.
 * @param info HPKE info the sender used.
 * @param aad Associated data the sender used.
 * @param blob Sealed blob.
 * @returns The plaintext.
 * @throws {CloakCryptoError} `invalid_format` for an unknown format or a short blob;
 *   `decryption_failed` for a wrong key, wrong context or tampering.
 */
export async function openBlob(
  recipientPrivateKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  blob: Uint8Array,
): Promise<Uint8Array> {
  requireFormat(blob, 1 + ENC_BYTES + TAG_BYTES);
  try {
    const opened = await SUITE.open(
      {
        recipientKey: await SUITE.kem.deserializePrivateKey(recipientPrivateKey),
        enc: blob.slice(1, 1 + ENC_BYTES),
        info,
      },
      blob.slice(1 + ENC_BYTES),
      aad,
    );
    return new Uint8Array(opened);
  } catch (error: unknown) {
    throw new CloakCryptoError(
      'decryption_failed',
      'The blob does not open with this key and context',
      {
        cause: error,
      },
    );
  }
}
