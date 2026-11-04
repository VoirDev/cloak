import { sha256 } from '@noble/hashes/sha2.js';

import { Canonical } from './canonical.ts';
import type { KdfParams } from './identity.ts';
import { LABELS } from './labels.ts';
import { checkSignature, sign } from './signatures.ts';

/** A new private key bundle and the parameters that open it (`PROTOCOL.md` §5.4). */
export interface CredentialsChange {
  /** The user. */
  readonly userId: string;
  /** The identity key version whose keys sign the change, the current one. */
  readonly keyVersion: number;
  /** The credentials version the change creates. */
  readonly credentialsVersion: number;
  /** The new bundle. */
  readonly privateKeyBundle: Uint8Array;
  /** Argon2id parameters of the new bundle. */
  readonly kdf: KdfParams;
}

/**
 * Builds the statement a new private key bundle is signed with, so that someone holding only the
 * host's session cannot replace it.
 *
 * @param change The change.
 * @returns Canonical message.
 */
export function credentialsMessage(change: CredentialsChange): Uint8Array {
  return Canonical.of(LABELS.credentials)
    .uuid(change.userId)
    .u32(change.keyVersion)
    .u32(change.credentialsVersion)
    .digest32(sha256(change.privateKeyBundle))
    .digest32(sha256(change.kdf.salt))
    .u32(change.kdf.memoryKib)
    .u32(change.kdf.iterations)
    .u8(change.kdf.parallelism)
    .build();
}

/**
 * Builds the statement a user signs to delete their own identity (`PROTOCOL.md` §5.7). It expires
 * at [notAfter], so a captured one cannot be sent again later.
 *
 * @param userId The user.
 * @param keyVersion The current identity key version.
 * @param credentialsVersion The current credentials version.
 * @param notAfter Unix time in seconds after which the server refuses it.
 * @returns Canonical message.
 */
export function identityDeletionMessage(
  userId: string,
  keyVersion: number,
  credentialsVersion: number,
  notAfter: number,
): Uint8Array {
  return Canonical.of(LABELS.identityDeletion)
    .uuid(userId)
    .u32(keyVersion)
    .u32(credentialsVersion)
    .u64(notAfter)
    .build();
}

/**
 * Signs either statement with the current signing key.
 *
 * @param message The statement.
 * @param signingSeed The current version's Ed25519 seed.
 * @returns The 65-byte signature blob.
 */
export function signIdentityStatement(message: Uint8Array, signingSeed: Uint8Array): Uint8Array {
  return sign(signingSeed, message);
}

/**
 * Verifies either statement against the current version's signing key.
 *
 * @param message The statement.
 * @param signature The signature blob.
 * @param signingPublicKey The current version's signing key.
 * @returns Whether it verifies.
 */
export function verifyIdentityStatement(
  message: Uint8Array,
  signature: Uint8Array,
  signingPublicKey: Uint8Array,
): boolean {
  return checkSignature(signingPublicKey, message, signature) === undefined;
}
