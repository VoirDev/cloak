package dev.voir.cloak.server.identity

import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.protocol.KeyDirectory

/**
 * The key versions the server holds, each stored only after its statement verified, read once per
 * user and version within one transaction. Reading a user's current version takes a shared lock on
 * their identity row, so a key replacement cannot commit between a superseded check and the write
 * that relies on it; identity rows are always locked after vault rows.
 */
internal class DatabaseKeyDirectory : KeyDirectory {
    /** Key versions read so far; `null` values mean absent. */
    private val keys = HashMap<Pair<UserId, Int>, PublicKeys?>()

    /** Current key versions read so far; `null` values mean no identity. */
    private val current = HashMap<UserId, Int?>()

    /** Reads a stored key version. */
    override fun keys(userId: UserId, keyVersion: Int): PublicKeys? =
        keys.getOrPut(userId to keyVersion) { IdentityRepository.findKeys(userId, keyVersion) }

    /** Whether the user has a later key version than [keyVersion]. */
    override fun isSuperseded(userId: UserId, keyVersion: Int): Boolean =
        (currentVersion(userId) ?: keyVersion) > keyVersion

    /**
     * Returns a user's current key version.
     *
     * @param userId User.
     * @return The version, or `null` when the user has no identity.
     */
    fun currentVersion(userId: UserId): Int? =
        current.getOrPut(userId) { IdentityRepository.currentKeyVersions(listOf(userId), lock = true)[userId] }
}
