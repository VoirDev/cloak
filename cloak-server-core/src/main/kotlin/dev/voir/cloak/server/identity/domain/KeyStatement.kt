package dev.voir.cloak.server.identity.domain

import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A key version as published (`PROTOCOL.md` §5.2): signed by its own signing key, and from
 * version 2 on also by the previous version's recovery signing key.
 *
 * @property keys The key version.
 * @property previousKeysDigest `keysDigest` of the previous version; `null` for version 1.
 * @property signature Signature by the version's signing key.
 * @property recoverySignature Signature by the previous version's recovery signing key; `null` for version 1.
 * @property createdAt Instant the version was published.
 */
public data class KeyStatement(
    /** The key version. */
    public val keys: PublicKeys,
    /** Digest of the previous version. */
    public val previousKeysDigest: ByteString?,
    /** Signature by the version's signing key. */
    public val signature: ByteString,
    /** Signature by the previous version's recovery signing key. */
    public val recoverySignature: ByteString?,
    /** Publication instant. */
    public val createdAt: Instant,
)

/**
 * Every key version of a user, oldest first.
 *
 * @property userId The user.
 * @property hostUserId The host's id of the user, from which [userId] derives; `null` once deleted.
 * @property deleted Whether the identity is deleted (`PROTOCOL.md` §5.7); its key versions stay.
 * @property versions Key statements, oldest first.
 */
public data class UserKeys(
    /** The user. */
    public val userId: UserId,
    /** The host's id of the user; `null` once deleted. */
    public val hostUserId: HostUserId?,
    /** Whether the identity is deleted. */
    public val deleted: Boolean,
    /** Key statements, oldest first. */
    public val versions: List<KeyStatement>,
)

/**
 * Result of loading several users' key versions.
 *
 * @property items Key versions of every user that has an identity.
 * @property missingUserIds Requested users without an identity.
 */
public data class UserKeysBatch(
    /** Key versions of users with an identity. */
    public val items: List<UserKeys>,
    /** Requested users without an identity. */
    public val missingUserIds: List<UserId>,
)
