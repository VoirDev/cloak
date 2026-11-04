import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { BLOB_FORMAT, ENC_BYTES, requireFormat } from './blobs.ts';
import { concatBytes } from './bytes.ts';

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
  if (recipientPublicKey.length !== 32)
    throw new CloakCryptoError('invalid_format', 'X25519 keys have 32 bytes');
  const sealed = await SUITE.seal(
    {
      recipientPublicKey: await SUITE.kem.deserializePublicKey(recipientPublicKey),
      info,
      ...(ephemeralIkm === undefined ? {} : { ekm: ephemeralIkm }),
    },
    plaintext,
    aad,
  );
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
