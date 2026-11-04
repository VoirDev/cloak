import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { concatBytes, randomBytes } from './bytes.ts';

/** The only blob format version today (`PROTOCOL.md` §4). */
export const BLOB_FORMAT = 1;

/** Size of an XChaCha20-Poly1305 nonce. */
const NONCE_BYTES = 24;

/** Size of a Poly1305 tag. */
const TAG_BYTES = 16;

/** Size of an Ed25519 signature. */
export const SIGNATURE_BYTES = 64;

/** Size of an HPKE X25519 `enc`. */
export const ENC_BYTES = 32;

/**
 * Encrypts into an encrypted blob: `0x01 ‖ nonce (24) ‖ ciphertext ‖ tag (16)`.
 * The associated data is not stored; the reader rebuilds it from context.
 *
 * @param key 32-byte key.
 * @param ad Associated data.
 * @param plaintext Bytes to encrypt.
 * @param nonce 24-byte nonce; a fresh random one unless a test fixes it.
 * @returns The blob.
 */
export function encryptBlob(
  key: Uint8Array,
  ad: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array = randomBytes(NONCE_BYTES),
): Uint8Array {
  if (key.length !== 32) throw new CloakCryptoError('invalid_format', 'Keys have 32 bytes');
  if (nonce.length !== NONCE_BYTES)
    throw new CloakCryptoError('invalid_format', 'Nonces have 24 bytes');
  return concatBytes(
    Uint8Array.of(BLOB_FORMAT),
    nonce,
    xchacha20poly1305(key, nonce, ad).encrypt(plaintext),
  );
}

/**
 * Opens an encrypted blob.
 *
 * @param key 32-byte key.
 * @param ad Associated data the writer used.
 * @param blob Encrypted blob.
 * @returns The plaintext.
 * @throws {CloakCryptoError} `invalid_format` for an unknown format or a short blob;
 *   `decryption_failed` for a wrong key, wrong associated data or tampering.
 */
export function decryptBlob(key: Uint8Array, ad: Uint8Array, blob: Uint8Array): Uint8Array {
  requireFormat(blob, 1 + NONCE_BYTES + TAG_BYTES);
  try {
    return xchacha20poly1305(key, blob.subarray(1, 1 + NONCE_BYTES), ad).decrypt(
      blob.subarray(1 + NONCE_BYTES),
    );
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

/**
 * Checks a blob's format byte and exact size, as the server does (`PROTOCOL.md` §13).
 *
 * @param blob Blob to check.
 * @param size Its only valid size.
 * @throws {CloakCryptoError} `invalid_format` otherwise.
 */
export function requireExactFormat(blob: Uint8Array, size: number): void {
  if (blob.length !== size)
    throw new CloakCryptoError('invalid_format', `The blob must have ${String(size)} bytes`);
  requireFormat(blob, size);
}

/**
 * Checks a blob's format byte and minimum size.
 *
 * @param blob Blob to check.
 * @param minimum Smallest valid size.
 * @throws {CloakCryptoError} `invalid_format` otherwise.
 */
export function requireFormat(blob: Uint8Array, minimum: number): void {
  if (blob.length < minimum) throw new CloakCryptoError('invalid_format', 'The blob is too short');
  if (blob[0] !== BLOB_FORMAT) {
    throw new CloakCryptoError('invalid_format', `Unsupported blob format ${String(blob[0])}`);
  }
}
