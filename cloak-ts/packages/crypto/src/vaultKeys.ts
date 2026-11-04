import { CloakCryptoError } from './CloakCryptoError.ts';
import { decryptBlob, encryptBlob } from './blobs.ts';
import { concatBytes, equalBytes, randomBytes, utf8, uuidBytes } from './bytes.ts';
import { Canonical } from './canonical.ts';
import { openBlob, sealBlob } from './hpke.ts';
import { hkdf } from './kdf.ts';
import { LABELS } from './labels.ts';

/** Size of a vault key sealed to a member. */
export const ENVELOPE_BYTES = 81;

/** Size of a vault key wrapped by another. */
export const WRAPPED_KEY_BYTES = 73;

/** Who an envelope is for: a member at one of their key versions. */
export interface EnvelopeRecipient {
  /** The member. */
  readonly userId: string;
  /** The member's identity key version the envelope is sealed to. */
  readonly userKeyVersion: number;
}

/**
 * Generates a new random vault key, for a new vault or the next key version.
 *
 * @returns 32 random bytes.
 */
export function generateVaultKey(): Uint8Array {
  return randomBytes(32);
}

/**
 * Derives the key that encrypts section content in a vault (`PROTOCOL.md` §6.1).
 *
 * @param vaultKey 32-byte vault key.
 * @param vaultId Vault the key belongs to.
 * @returns `HKDF(vaultKey, salt = vaultId, "cloak/v1/vault-content")`.
 */
export function contentKey(vaultKey: Uint8Array, vaultId: string): Uint8Array {
  return hkdf(requireKey(vaultKey), uuidBytes(vaultId), LABELS.vaultContent);
}

/**
 * Derives the key that wraps the previous vault key (`PROTOCOL.md` §6.1).
 *
 * @param vaultKey 32-byte vault key.
 * @param vaultId Vault the key belongs to.
 * @returns `HKDF(vaultKey, salt = vaultId, "cloak/v1/vault-wrap")`.
 */
export function wrapKey(vaultKey: Uint8Array, vaultId: string): Uint8Array {
  return hkdf(requireKey(vaultKey), uuidBytes(vaultId), LABELS.vaultWrap);
}

/**
 * Computes a vault key's commitment, which the signed entry that creates the version carries
 * (`PROTOCOL.md` §6.1).
 *
 * @param vaultKey 32-byte vault key.
 * @param vaultId Vault.
 * @param keyVersion Version of the key.
 * @returns `HKDF(vaultKey, salt = uuid vaultId ‖ u32 keyVersion, "cloak/v1/vault-key-commit")`.
 */
export function keyCommitment(
  vaultKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
): Uint8Array {
  const version = new Uint8Array(4);
  new DataView(version.buffer).setUint32(0, keyVersion);
  return hkdf(
    requireKey(vaultKey),
    concatBytes(uuidBytes(vaultId), version),
    LABELS.vaultKeyCommit,
  );
}

/**
 * Checks an opened vault key against the commitment in the verified log, before any use.
 *
 * @param vaultKey Key as opened from an envelope or wrap.
 * @param vaultId Vault.
 * @param keyVersion Version the key claims to be.
 * @param committed Commitment of that version from the verified log.
 * @returns The key.
 * @throws {CloakCryptoError} `key_mismatch` when it is not the committed key.
 */
export function requireCommittedKey(
  vaultKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
  committed: Uint8Array,
): Uint8Array {
  if (!equalBytes(keyCommitment(vaultKey, vaultId, keyVersion), committed)) {
    throw new CloakCryptoError('key_mismatch', 'The vault key does not match its commitment');
  }
  return vaultKey;
}

/**
 * Builds an envelope's context (`PROTOCOL.md` §6.3), its HPKE associated data.
 *
 * @param vaultId Vault.
 * @param keyVersion Vault key version the envelope holds.
 * @param recipient Member and their key version.
 * @returns Canonical context.
 */
export function envelopeContext(
  vaultId: string,
  keyVersion: number,
  recipient: EnvelopeRecipient,
): Uint8Array {
  return Canonical.of(LABELS.vaultKey)
    .uuid(vaultId)
    .u32(keyVersion)
    .uuid(recipient.userId)
    .u32(recipient.userKeyVersion)
    .build();
}

/**
 * Seals a vault key to a member's X25519 key of their committed version.
 *
 * @param recipientPublicKey The member's X25519 public key of [recipient].userKeyVersion.
 * @param vaultId Vault.
 * @param keyVersion Vault key version.
 * @param recipient Member and their key version.
 * @param vaultKey 32-byte vault key at [keyVersion].
 * @param ephemeralIkm Fixed ephemeral input for tests; random by default.
 * @returns An 81-byte sealed blob.
 */
export function sealEnvelope(
  recipientPublicKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
  recipient: EnvelopeRecipient,
  vaultKey: Uint8Array,
  ephemeralIkm?: Uint8Array,
): Promise<Uint8Array> {
  return sealBlob(
    recipientPublicKey,
    utf8(LABELS.vaultKey),
    envelopeContext(vaultId, keyVersion, recipient),
    requireKey(vaultKey),
    ephemeralIkm,
  );
}

/**
 * Opens a vault key sealed to the caller. Check it with {@link requireCommittedKey} before use.
 *
 * @param encryptionPrivateKey The caller's X25519 private key of [recipient].userKeyVersion.
 * @param vaultId Vault.
 * @param keyVersion Vault key version the server named.
 * @param recipient The caller and the key version the envelope is sealed to.
 * @param envelope Sealed blob.
 * @returns The 32-byte vault key.
 * @throws {CloakCryptoError} `decryption_failed` when the envelope was made for another vault,
 *   version, member or member key version.
 */
export async function openEnvelope(
  encryptionPrivateKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
  recipient: EnvelopeRecipient,
  envelope: Uint8Array,
): Promise<Uint8Array> {
  return requireKey(
    await openBlob(
      encryptionPrivateKey,
      utf8(LABELS.vaultKey),
      envelopeContext(vaultId, keyVersion, recipient),
      envelope,
    ),
  );
}

/**
 * Builds the associated data of a vault key's previous version (`PROTOCOL.md` §6.2).
 *
 * @param vaultId Vault.
 * @param keyVersion The version that wraps its predecessor.
 * @returns Canonical associated data.
 */
export function previousKeyAd(vaultId: string, keyVersion: number): Uint8Array {
  return Canonical.of(LABELS.vaultPrevious).uuid(vaultId).u32(keyVersion).build();
}

/**
 * Wraps a vault's previous key by its new one, so holders of the new key read older content.
 *
 * @param currentKey Vault key at [keyVersion].
 * @param vaultId Vault.
 * @param keyVersion The new key version; at least 2.
 * @param previousKey Vault key at `keyVersion - 1`.
 * @param nonce Fixed nonce for tests; random by default.
 * @returns A 73-byte encrypted blob.
 */
export function wrapPreviousKey(
  currentKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
  previousKey: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  requireSecondVersion(keyVersion);
  return encryptBlob(
    wrapKey(currentKey, vaultId),
    previousKeyAd(vaultId, keyVersion),
    requireKey(previousKey),
    nonce,
  );
}

/**
 * Opens a vault's previous key with its current one. Check it with {@link requireCommittedKey}.
 *
 * @param currentKey Vault key at [keyVersion].
 * @param vaultId Vault.
 * @param keyVersion The key version that wraps its predecessor.
 * @param wrapped The previous-key wrap of that version.
 * @returns The 32-byte vault key at `keyVersion - 1`.
 * @throws {CloakCryptoError} `decryption_failed` when the wrap belongs to another vault or version.
 */
export function unwrapPreviousKey(
  currentKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
  wrapped: Uint8Array,
): Uint8Array {
  requireSecondVersion(keyVersion);
  return requireKey(
    decryptBlob(wrapKey(currentKey, vaultId), previousKeyAd(vaultId, keyVersion), wrapped),
  );
}

/** Fails unless the version has a predecessor. */
function requireSecondVersion(keyVersion: number): void {
  if (keyVersion < 2)
    throw new CloakCryptoError('invalid_format', 'Key version 1 has no previous key');
}

/** Fails unless a value is a 32-byte vault key; returns it. */
function requireKey(key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new CloakCryptoError('invalid_format', 'Vault keys have 32 bytes');
  return key;
}
