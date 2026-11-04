package dev.voir.cloak.server.identity.domain

import kotlinx.io.bytestring.ByteString

/**
 * One version of a user's public keys (`PROTOCOL.md` §5.1).
 *
 * @property userId Owner of the keys.
 * @property keyVersion Identity key version: 1 at registration, one more at each replacement.
 * @property cryptoSuite Algorithm suite of the keys; only `1` exists.
 * @property encryptionPublicKey Raw 32-byte X25519 public key that vault keys are sealed to.
 * @property signingPublicKey Raw 32-byte Ed25519 public key that verifies entries and writes.
 * @property recoverySigningPublicKey Raw 32-byte Ed25519 public key that signs only the next version.
 */
public data class PublicKeys(
    /** Owner of the keys. */
    public val userId: UserId,
    /** Identity key version. */
    public val keyVersion: Int,
    /** Algorithm suite. */
    public val cryptoSuite: Int,
    /** Raw X25519 public key. */
    public val encryptionPublicKey: ByteString,
    /** Raw Ed25519 public key. */
    public val signingPublicKey: ByteString,
    /** Raw Ed25519 recovery signing public key. */
    public val recoverySigningPublicKey: ByteString,
)
