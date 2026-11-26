import { sha256 } from '@noble/hashes/sha2.js';

import { equalBytes, isUuid } from './bytes.ts';
import { Canonical, isBytes32, isU32, isU8 } from './canonical.ts';
import { toFingerprintCode } from './codes.ts';
import { LABELS } from './labels.ts';

/** The crypto suite this package implements (`PROTOCOL.md` §2). */
export const CRYPTO_SUITE = 1;

/** One version of a user's public keys (`PROTOCOL.md` §5.1). */
export interface PublicKeys {
  /** Owner of the keys. */
  readonly userId: string;
  /** Identity key version: 1 at registration, one more at each replacement. */
  readonly keyVersion: number;
  /** Crypto suite of the keys; {@link CRYPTO_SUITE}. */
  readonly cryptoSuite: number;
  /** Raw X25519 public key; vault keys are sealed to it. */
  readonly encryptionPublicKey: Uint8Array;
  /** Raw Ed25519 public key that verifies writes and log entries. */
  readonly signingPublicKey: Uint8Array;
  /** Raw Ed25519 public key of the recovery signing key, which signs only the next version. */
  readonly recoverySigningPublicKey: Uint8Array;
}

/**
 * Tells whether every field of a key version fits its type in the canonical encoding
 * (`PROTOCOL.md` §3), so that {@link fingerprintMessage} and {@link keysDigest} encode it: a
 * lowercase UUID, a `u8` suite, a `u32` version and three 32-byte keys. Whether the keys are usable
 * is a separate check.
 *
 * @param keys The key version, as served.
 * @returns Whether it has a fingerprint message.
 */
export function isWellFormedKeys(keys: PublicKeys): boolean {
  return (
    isUuid(keys.userId) &&
    isU8(keys.cryptoSuite) &&
    isU32(keys.keyVersion) &&
    isBytes32(keys.encryptionPublicKey) &&
    isBytes32(keys.signingPublicKey) &&
    isBytes32(keys.recoverySigningPublicKey)
  );
}

/**
 * Builds a key version's fingerprint message (`PROTOCOL.md` §5.1).
 *
 * @param keys The key version.
 * @returns Canonical message.
 */
export function fingerprintMessage(keys: PublicKeys): Uint8Array {
  return Canonical.of(LABELS.fingerprint)
    .uuid(keys.userId)
    .u8(keys.cryptoSuite)
    .u32(keys.keyVersion)
    .key32(keys.encryptionPublicKey)
    .key32(keys.signingPublicKey)
    .key32(keys.recoverySigningPublicKey)
    .build();
}

/**
 * Digests a key version: how the vault log commits to a person's keys and what a fingerprint shows.
 *
 * @param keys The key version.
 * @returns `SHA-256(fingerprintMessage)`.
 */
export function keysDigest(keys: PublicKeys): Uint8Array {
  return sha256(fingerprintMessage(keys));
}

/**
 * Computes a key version's fingerprint, 8 groups of 4 Crockford characters, that people compare
 * out of band before trusting each other's keys (`PROTOCOL.md` §9).
 *
 * @param keys The key version.
 * @returns The fingerprint.
 */
export function fingerprint(keys: PublicKeys): string {
  return toFingerprintCode(keysDigest(keys));
}

/**
 * Tells whether two descriptions are the same key version with the same keys.
 *
 * @param a First key version.
 * @param b Second key version.
 * @returns Whether their digests match.
 */
export function sameKeys(a: PublicKeys, b: PublicKeys): boolean {
  return equalBytes(keysDigest(a), keysDigest(b));
}
