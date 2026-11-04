package dev.voir.cloak.server.vault.persistence

import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.write_pause_requests`: when each member last paused a vault's writes
 * without being an admin, so they may do it only once per interval (`PROTOCOL.md` §7.5).
 */
internal object WritePauseRequestsTable : Table("cloak.write_pause_requests") {
    /** The vault paused. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_write_pause_requests__vault_id__vaults",
        )

    /** The member who paused it. */
    val userId = uuid("user_id")

    /** When they last paused it. */
    val pausedAt = timestamp("paused_at")

    /** Primary key: one row per vault and member. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, userId, name = "pk_write_pause_requests")
}
