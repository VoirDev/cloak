import { sha256 } from '@noble/hashes/sha2.js';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { concatBytes, equalBytes } from './bytes.ts';

/** Crockford base32 alphabet (`PROTOCOL.md` §10). */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Prefix of a secret key code. */
const SECRET_KEY_PREFIX = 'CS1';

/** Prefix of a recovery key code. */
const RECOVERY_KEY_PREFIX = 'CR1';

/**
 * Encodes bytes in Crockford base32: one big-endian bit string, the last group padded with zero bits.
 *
 * @param bytes Bytes to encode.
 * @returns Uppercase Crockford text.
 */
export function toCrockford(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD.charAt((buffer >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD.charAt((buffer << (5 - bits)) & 31);
  return out;
}

/**
 * Decodes Crockford base32 typed by a person: case-insensitive, `O` read as `0`, `I` and `L` as `1`,
 * hyphens and spaces ignored, non-zero padding bits refused.
 *
 * @param text Code text.
 * @param length Number of bytes the code holds.
 * @returns The bytes.
 * @throws {CloakCryptoError} `bad_code` for other characters, the wrong length or padding bits.
 */
export function fromCrockford(text: string, length: number): Uint8Array {
  const normalized = text
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  if (normalized.length !== Math.ceil((length * 8) / 5)) {
    throw new CloakCryptoError('bad_code', 'The code has the wrong length');
  }
  const out = new Uint8Array(length);
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const character of normalized) {
    const value = CROCKFORD.indexOf(character);
    if (value < 0) throw new CloakCryptoError('bad_code', 'The code has an invalid character');
    buffer = ((buffer << 5) | value) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[offset] = (buffer >>> bits) & 0xff;
      offset += 1;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw new CloakCryptoError('bad_code', 'The code has non-zero padding bits');
  }
  return out;
}

/**
 * Formats a secret key as `CS1-XXXX-…` (7 groups of 4) with a 1-byte checksum.
 *
 * @param secretKey 16-byte secret key.
 * @returns The code to show the user once.
 */
export function toSecretKeyCode(secretKey: Uint8Array): string {
  return formatCode(SECRET_KEY_PREFIX, secretKey, 1);
}

/**
 * Parses a secret key code, catching typos with its checksum.
 *
 * @param code Code as typed or scanned.
 * @returns The 16-byte secret key.
 * @throws {CloakCryptoError} `bad_code` for a wrong prefix, length, padding or checksum.
 */
export function fromSecretKeyCode(code: string): Uint8Array {
  return parseCode(SECRET_KEY_PREFIX, code, 16, 1);
}

/**
 * Formats a recovery key as `CR1-XXXX-…` (14 groups of 4) with a 3-byte checksum.
 *
 * @param recoveryKey 32-byte recovery key.
 * @returns The code for the printable recovery kit.
 */
export function toRecoveryKeyCode(recoveryKey: Uint8Array): string {
  return formatCode(RECOVERY_KEY_PREFIX, recoveryKey, 3);
}

/**
 * Parses a recovery key code.
 *
 * @param code Code as typed.
 * @returns The 32-byte recovery key.
 * @throws {CloakCryptoError} `bad_code` for a wrong prefix, length, padding or checksum.
 */
export function fromRecoveryKeyCode(code: string): Uint8Array {
  return parseCode(RECOVERY_KEY_PREFIX, code, 32, 3);
}

/**
 * Formats a key version's fingerprint: 8 groups of 4 Crockford characters of `keysDigest[0..20]`.
 *
 * @param keysDigest 32-byte digest of the key version (`PROTOCOL.md` §5.1).
 * @returns The fingerprint to compare out of band.
 */
export function toFingerprintCode(keysDigest: Uint8Array): string {
  return group(toCrockford(keysDigest.subarray(0, 20)));
}

/** Formats a prefixed code with a SHA-256 checksum of [checksumBytes] bytes. */
function formatCode(prefix: string, key: Uint8Array, checksumBytes: number): string {
  return `${prefix}-${group(toCrockford(concatBytes(key, sha256(key).subarray(0, checksumBytes))))}`;
}

/** Parses a prefixed code and checks its checksum. */
function parseCode(
  prefix: string,
  code: string,
  keyBytes: number,
  checksumBytes: number,
): Uint8Array {
  // Hyphens and spaces are ignored everywhere, including after the prefix.
  const compact = code.toUpperCase().replace(/[\s-]/g, '');
  if (!compact.startsWith(prefix)) {
    throw new CloakCryptoError('bad_code', `The code must start with ${prefix}-`);
  }
  const bytes = fromCrockford(compact.slice(prefix.length), keyBytes + checksumBytes);
  const key = bytes.slice(0, keyBytes);
  if (!equalBytes(bytes.subarray(keyBytes), sha256(key).subarray(0, checksumBytes))) {
    throw new CloakCryptoError('bad_code', 'The code has a typo');
  }
  return key;
}

/** Splits text into hyphen-separated groups of four. */
function group(text: string): string {
  return (text.match(/.{1,4}/g) ?? []).join('-');
}
