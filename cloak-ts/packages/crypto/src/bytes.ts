import { CloakCryptoError } from './CloakCryptoError.ts';

/** Encoder of UTF-8 strings. */
const UTF8 = new TextEncoder();

/** Base64url alphabet (RFC 4648 §5). */
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Reverse lookup of {@link BASE64URL}; `-1` for characters outside the alphabet. */
const BASE64URL_INDEX: readonly number[] = Array.from({ length: 128 }, (_, code) =>
  BASE64URL.indexOf(String.fromCharCode(code)),
);

/**
 * Encodes a string as UTF-8 without normalizing it.
 *
 * @param text Text to encode.
 * @returns UTF-8 bytes.
 */
export function utf8(text: string): Uint8Array {
  return UTF8.encode(text);
}

/**
 * Concatenates byte arrays.
 *
 * @param parts Arrays in order.
 * @returns A new array holding every part.
 */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Compares two byte arrays in time that depends only on their lengths.
 *
 * @param a First array.
 * @param b Second array.
 * @returns Whether they are equal.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

/**
 * Tells whether every byte is zero, which the canonical encoding reads as an absent value.
 *
 * @param bytes Bytes to test; `undefined` counts as absent too.
 * @returns Whether the value is absent.
 */
export function isAbsent(bytes: Uint8Array | undefined): boolean {
  return bytes === undefined || bytes.every((byte) => byte === 0);
}

/**
 * Compares two byte arrays lexicographically, as unsigned bytes.
 *
 * @param a First array.
 * @param b Second array.
 * @returns Negative, zero or positive as `a` sorts before, with or after `b`.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

/**
 * XORs two arrays of equal length.
 *
 * @param a First array.
 * @param b Second array, as long as `a`.
 * @returns `a XOR b`.
 */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new RangeError('XOR needs arrays of equal length');
  return a.map((byte, index) => byte ^ (b[index] ?? 0));
}

/**
 * Returns cryptographically secure random bytes from the platform CSPRNG.
 *
 * @param length Number of bytes.
 * @returns Fresh random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Encodes bytes as base64url without padding, the API's binary format.
 *
 * @param bytes Bytes to encode.
 * @returns Base64url text.
 */
export function toBase64Url(bytes: Uint8Array): string {
  let text = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const chunk =
      ((bytes[index] ?? 0) << 16) | ((bytes[index + 1] ?? 0) << 8) | (bytes[index + 2] ?? 0);
    const characters = Math.min(4, Math.ceil(((bytes.length - index) * 8) / 6));
    for (let position = 0; position < characters; position += 1) {
      text += BASE64URL.charAt((chunk >> (18 - 6 * position)) & 63);
    }
  }
  return text;
}

/**
 * Decodes base64url without padding.
 *
 * @param text Base64url text.
 * @returns The bytes.
 * @throws {CloakCryptoError} `invalid_format` for characters outside the alphabet, padding, or
 *   an impossible length.
 */
export function fromBase64Url(text: string): Uint8Array {
  if (text.length % 4 === 1)
    throw new CloakCryptoError('invalid_format', 'Invalid base64url length');
  const out = new Uint8Array(Math.floor((text.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const character of text) {
    const value = BASE64URL_INDEX[character.charCodeAt(0)] ?? -1;
    if (value < 0) throw new CloakCryptoError('invalid_format', 'Invalid base64url character');
    buffer = ((buffer << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[offset] = (buffer >> bits) & 0xff;
      offset += 1;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw new CloakCryptoError('invalid_format', 'Non-canonical base64url');
  }
  return out;
}

/**
 * Parses a UUID into its 16 bytes in RFC 9562 order.
 *
 * @param uuid Hyphenated UUID in lowercase canonical form.
 * @returns 16 bytes.
 * @throws {CloakCryptoError} `invalid_format` when it is not a lowercase UUID.
 */
export function uuidBytes(uuid: string): Uint8Array {
  // Only the lowercase canonical form: ids are compared and stored as strings, so another
  // spelling of the same bytes would slip past rollback and fork tracking.
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid)) {
    throw new CloakCryptoError('invalid_format', 'Not a lowercase UUID');
  }
  const hex = uuid.replaceAll('-', '');
  return Uint8Array.from({ length: 16 }, (_, index) =>
    parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

/**
 * Formats 16 bytes as a lowercase hyphenated UUID.
 *
 * @param bytes 16 bytes in RFC 9562 order.
 * @returns The UUID.
 */
export function uuidFromBytes(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new CloakCryptoError('invalid_format', 'A UUID has 16 bytes');
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
