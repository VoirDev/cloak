import { ed25519 } from '@noble/curves/ed25519.js';

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
  if (littleEndian(raw.subarray(32)) >= GROUP_ORDER) return 'non_canonical_signature';
  if (yCoordinate(raw.subarray(0, 32)) >= FIELD_PRIME) return 'non_canonical_signature';
  if (yCoordinate(publicKey) >= FIELD_PRIME) return 'non_canonical_key';
  if (isSmallOrderKey(publicKey)) return 'small_order_key';
  try {
    return ed25519.verify(raw, message, publicKey, { zip215: false }) ? undefined : 'bad_signature';
  } catch {
    return 'bad_signature';
  }
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
