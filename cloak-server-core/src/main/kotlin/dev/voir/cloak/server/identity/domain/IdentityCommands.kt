package dev.voir.cloak.server.identity.domain

import kotlinx.io.bytestring.ByteString

/**
 * Registers the caller's identity: key version 1 with its self-signed statement.
 *
 * @property cryptoSuite Algorithm suite; only `1` is accepted.
 * @property encryptionPublicKey Raw 32-byte X25519 public key.
 * @property signingPublicKey Raw 32-byte Ed25519 public key; unique across users and versions.
 * @property recoverySigningPublicKey Raw 32-byte Ed25519 public key derived from the recovery key.
 * @property signature Signature of the version-1 key statement by the signing key.
 * @property kdf Argon2id parameters.
 * @property privateKeyBundle Private keys encrypted under the master key.
 * @property recoveryKeyBundle Private keys encrypted under the recovery key.
 */
public data class RegisterIdentityCommand(
    /** Algorithm suite. */
    public val cryptoSuite: Int,
    /** Raw X25519 public key. */
    public val encryptionPublicKey: ByteString,
    /** Raw Ed25519 public key. */
    public val signingPublicKey: ByteString,
    /** Raw Ed25519 recovery signing public key. */
    public val recoverySigningPublicKey: ByteString,
    /** Statement signature. */
    public val signature: ByteString,
    /** Argon2id parameters. */
    public val kdf: KdfParams,
    /** Private keys under the master key. */
    public val privateKeyBundle: ByteString,
    /** Private keys under the recovery key. */
    public val recoveryKeyBundle: ByteString,
)

/**
 * Replaces the private key bundle and KDF parameters after a password change or a recovery
 * (`PROTOCOL.md` §5.5). Keys do not change.
 *
 * @property expectedCredentialsVersion Version the client last read.
 * @property kdf New Argon2id parameters.
 * @property privateKeyBundle Private keys encrypted under the new master key.
 * @property signature `credentialsStatement` for version [expectedCredentialsVersion] + 1, signed
 *   with the caller's current signing key (`PROTOCOL.md` §5.4).
 */
public data class UpdateCredentialsCommand(
    /** Version the client last read. */
    public val expectedCredentialsVersion: Int,
    /** New Argon2id parameters. */
    public val kdf: KdfParams,
    /** Private keys under the new master key. */
    public val privateKeyBundle: ByteString,
    /** The signed credentials statement. */
    public val signature: ByteString,
)

/**
 * Deletes the caller's identity with a statement signed by their current keys (`PROTOCOL.md` §5.7).
 *
 * @property credentialsVersion The caller's current credentials version.
 * @property notAfter Unix time in seconds after which the statement is refused; at most 10 minutes ahead.
 * @property signature The identity deletion statement, signed with the current signing key.
 */
public data class DeleteIdentityCommand(
    /** The current credentials version. */
    public val credentialsVersion: Int,
    /** Unix seconds after which the statement is refused. */
    public val notAfter: Long,
    /** The signed statement. */
    public val signature: ByteString,
)

/**
 * Replaces the caller's identity keys with the next version (`PROTOCOL.md` §5.6).
 *
 * @property expectedKeyVersion The current key version, which the new one follows.
 * @property encryptionPublicKey New raw X25519 public key.
 * @property signingPublicKey New raw Ed25519 public key.
 * @property recoverySigningPublicKey New raw Ed25519 recovery signing public key.
 * @property signature Signature of the new statement by the new signing key.
 * @property recoverySignature Signature of the new statement by the current version's recovery signing key.
 * @property kdf New Argon2id parameters.
 * @property privateKeyBundle New private keys under the new master key.
 * @property recoveryKeyBundle New private keys under the new recovery key.
 */
public data class ReplaceKeysCommand(
    /** The current key version. */
    public val expectedKeyVersion: Int,
    /** New raw X25519 public key. */
    public val encryptionPublicKey: ByteString,
    /** New raw Ed25519 public key. */
    public val signingPublicKey: ByteString,
    /** New raw Ed25519 recovery signing public key. */
    public val recoverySigningPublicKey: ByteString,
    /** Signature by the new signing key. */
    public val signature: ByteString,
    /** Signature by the current recovery signing key. */
    public val recoverySignature: ByteString,
    /** New Argon2id parameters. */
    public val kdf: KdfParams,
    /** New private keys under the new master key. */
    public val privateKeyBundle: ByteString,
    /** New private keys under the new recovery key. */
    public val recoveryKeyBundle: ByteString,
)
