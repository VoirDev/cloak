package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.vault.domain.VaultId
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.upsert
import kotlin.time.Instant

/**
 * Reads and writes `cloak.write_pause_requests`: when members who are not admins last paused a
 * vault. Every function runs inside the caller's transaction, with the vault locked.
 */
internal object WritePauseRepository {
    /**
     * Returns when a member last paused a vault as a non-admin.
     *
     * @param vaultId The vault.
     * @param userId The member.
     * @return The instant, or `null` when they never did.
     */
    fun lastPause(vaultId: VaultId, userId: UserId): Instant? =
        WritePauseRequestsTable.selectAll()
            .where { (WritePauseRequestsTable.vaultId eq vaultId.value) and (WritePauseRequestsTable.userId eq userId.value) }
            .singleOrNull()
            ?.get(WritePauseRequestsTable.pausedAt)

    /**
     * Records that a member paused a vault as a non-admin.
     *
     * @param vaultId The vault.
     * @param userId The member.
     * @param at When.
     */
    fun record(vaultId: VaultId, userId: UserId, at: Instant) {
        WritePauseRequestsTable.upsert {
            it[WritePauseRequestsTable.vaultId] = vaultId.value
            it[WritePauseRequestsTable.userId] = userId.value
            it[pausedAt] = at
        }
    }
}
