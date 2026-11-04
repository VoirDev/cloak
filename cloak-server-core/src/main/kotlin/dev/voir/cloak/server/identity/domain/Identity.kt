package dev.voir.cloak.server.identity.domain

import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A user's identity as its owner reads it: the current key version and the encrypted bundles.
 *
 * @property hostUserId The host's id of the user, from which [PublicKeys.userId] derives.
 * @property keys The current key version.
 * @property kdf Argon2id parameters for the master key.
 * @property privateKeyBundle Private keys encrypted under the master key.
 * @property recoveryKeyBundle Private keys encrypted under the recovery key.
 * @property credentialsVersion Optimistic-lock version of the credentials; starts at 1.
 * @property createdAt Registration instant.
 * @property updatedAt Last change of the credentials or keys.
 */
public data class Identity(
    /** The host's id of the user. */
    public val hostUserId: HostUserId,
    /** The current key version. */
    public val keys: PublicKeys,
    /** Argon2id parameters. */
    public val kdf: KdfParams,
    /** Private keys under the master key. */
    public val privateKeyBundle: ByteString,
    /** Private keys under the recovery key. */
    public val recoveryKeyBundle: ByteString,
    /** Optimistic-lock version of the credentials. */
    public val credentialsVersion: Int,
    /** Registration instant. */
    public val createdAt: Instant,
    /** Last change. */
    public val updatedAt: Instant,
)
