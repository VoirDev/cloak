import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { BLOB_FORMAT, SIGNATURE_BYTES } from './blobs.ts';
import { concatBytes } from './bytes.ts';

/**
 * Why a signature is refused (`PROTOCOL.md` §2):
 *
 * - `bad_signature`: malformed blob, or the equation does not hold;
 * - `non_canonical_signature`: `S` is not below the group order, or `R` is not canonical;
 * - `non_canonical_key`: the public key is not a canonical encoding;
 * - `small_order_key`: the public key is a point of small order.
 */
export type SignatureRefusal =
  'bad_signature' | 'non_canonical_signature' | 'non_canonical_key' | 'small_order_key';

/**
 * Why a public key is refused (`PROTOCOL.md` §2, §5.1): `non_canonical_key` for an encoding that is
 * not canonical, `small_order_key` for a point of small order.
 */
export type KeyRefusal = 'non_canonical_key' | 'small_order_key';

/** Order of the edwards25519 prime-order subgroup. */
const GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

/** The edwards25519 field prime. */
const FIELD_PRIME = 2n ** 255n - 19n;

/** Encodings of the eight small-order points of edwards25519, as lowercase hex. */
export const SMALL_ORDER_POINTS: readonly string[] = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
];

/**
 * Signs a canonical message into a signature blob: `0x01 ‖ Ed25519 signature (64)`.
 *
 * @param signingSeed 32-byte Ed25519 seed.
 * @param message Canonical message.
 * @returns The signature blob.
 */
export function sign(signingSeed: Uint8Array, message: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(BLOB_FORMAT), ed25519.sign(message, signingSeed));
}

/**
 * Derives the Ed25519 public key of a seed.
 *
 * @param signingSeed 32-byte RFC 8032 seed.
 * @returns The 32-byte public key.
 */
export function signingPublicKey(signingSeed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(signingSeed);
}

/**
 * Checks a signature blob strictly, as RFC 8032 §5.1.7 says, without ZIP-215 relaxations: every
 * implementation refuses the same signatures.
 *
 * @param publicKey Signer's raw 32-byte Ed25519 key, pinned by the caller.
 * @param message Canonical message rebuilt from the data.
 * @param signature Signature blob.
 * @returns `undefined` when it verifies, otherwise why it is refused.
 */
export function checkSignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): SignatureRefusal | undefined {
  if (signature.length !== 1 + SIGNATURE_BYTES || signature[0] !== BLOB_FORMAT)
    return 'bad_signature';
  if (publicKey.length !== 32) return 'non_canonical_key';
  const raw = signature.subarray(1);
  const encodedR = raw.subarray(0, 32);
  const s = littleEndian(raw.subarray(32));
  if (s >= GROUP_ORDER) return 'non_canonical_signature';
  if (!isCanonicalPoint(encodedR)) return 'non_canonical_signature';
  const keyRefusal = checkSigningKey(publicKey);
  if (keyRefusal !== undefined) return keyRefusal;
  // The cofactorless equation, [S]B - [k]A = R, compared as encodings (RFC 8032 §5.1.7, as
  // OpenSSL and the JDK check it). A cofactored check would also accept an R or a key with a
  // small-order part, which other implementations refuse.
  let key;
  try {
    key = ed25519.Point.fromBytes(publicKey, false);
  } catch {
    return 'bad_signature';
  }
  const k = littleEndian(sha512(concatBytes(encodedR, publicKey, message))) % GROUP_ORDER;
  const expected = ed25519.Point.BASE.multiplyUnsafe(s).subtract(key.multiplyUnsafe(k)).toBytes();
  return equalEncodings(expected, encodedR) ? undefined : 'bad_signature';
}

/** Whether two 32-byte encodings are equal; both are public, so the comparison need not be constant-time. */
function equalEncodings(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/**
 * Whether a 32-byte edwards25519 encoding is canonical (`PROTOCOL.md` §2): `y` below the field
 * prime, and no sign bit on a point whose `x` is 0, which only `y` = 1 and `y` = p − 1 have.
 */
function isCanonicalPoint(point: Uint8Array): boolean {
  const y = yCoordinate(point);
  const signed = ((point[31] ?? 0) & 0x80) !== 0;
  return y < FIELD_PRIME && !(signed && (y === 1n || y === FIELD_PRIME - 1n));
}

/**
 * Tells whether a signature blob verifies strictly; see {@link checkSignature}.
 *
 * @param publicKey Signer's raw 32-byte Ed25519 key.
 * @param message Canonical message.
 * @param signature Signature blob.
 * @returns Whether it verifies.
 */
export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return checkSignature(publicKey, message, signature) === undefined;
}

/**
 * Verifies a signature blob strictly or throws.
 *
 * @param publicKey Signer's raw 32-byte Ed25519 key.
 * @param message Canonical message.
 * @param signature Signature blob.
 * @throws {CloakCryptoError} `bad_signature` when it does not verify, naming the refusal.
 */
export function requireValidSignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  const refusal = checkSignature(publicKey, message, signature);
  if (refusal !== undefined) {
    throw new CloakCryptoError('bad_signature', `The signature is refused: ${refusal}`);
  }
}

/**
 * Tells whether an Ed25519 public key is a point of small order, which no client or server
 * accepts as anyone's key (`PROTOCOL.md` §2).
 *
 * @param publicKey Raw 32-byte key.
 * @returns Whether it is one of {@link SMALL_ORDER_POINTS}.
 */
export function isSmallOrderKey(publicKey: Uint8Array): boolean {
  const encoded = Array.from(publicKey, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return SMALL_ORDER_POINTS.includes(encoded);
}

/**
 * Checks an Ed25519 public key as every verifier and the server do (`PROTOCOL.md` §2): 32 bytes,
 * a canonical encoding, and not of small order.
 *
 * @param publicKey Raw Ed25519 public key.
 * @returns `undefined` when usable, otherwise why it is refused.
 */
export function checkSigningKey(publicKey: Uint8Array): KeyRefusal | undefined {
  if (publicKey.length !== 32 || !isCanonicalPoint(publicKey)) return 'non_canonical_key';
  return isSmallOrderKey(publicKey) ? 'small_order_key' : undefined;
}

/** Reads bytes as a little-endian unsigned integer. */
function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

/** The y coordinate of an encoded point: its little-endian value without the sign bit. */
function yCoordinate(point: Uint8Array): bigint {
  return littleEndian(point) & ((1n << 255n) - 1n);
}
