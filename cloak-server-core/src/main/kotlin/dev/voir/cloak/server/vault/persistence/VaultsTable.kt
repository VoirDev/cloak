package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.persistence.IdentitiesTable
import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.vaults`: units of access, with their current key version, log head,
 * last section change number, section counts and write pause. Every request that changes a vault
 * locks its row first.
 */
internal object VaultsTable : Table("cloak.vaults") {
    /** Client-generated vault id. */
    val id = uuid("id")

    /** Current vault key version. */
    val keyVersion = integer("key_version").check("ck_vaults__key_version") { it greaterEq 1 }

    /** `seq` of the last log entry. */
    val logSeq = long("log_seq").check("ck_vaults__log_seq") { it greaterEq 1L }

    /** `entryHash` of the last log entry; 32 bytes. */
    val logHeadHash = binary("log_head_hash")

    /** Change number of the vault's last section write; 0 before the first. */
    val changeSeq = long("change_seq").check("ck_vaults__change_seq") { it greaterEq 0L }

    /** Number of the vault's live sections, whose latest write is not a deletion; kept within the live limit. */
    val liveSectionCount = integer("live_section_count").check("ck_vaults__live_section_count") { it greaterEq 0 }

    /** Number of the vault's stored sections, deletions included; kept within the stored limit. */
    val storedSectionCount = integer("stored_section_count")

    /** Holder of the vault's write pause, while one is set. */
    val pauseUserId = uuid("pause_user_id").nullable()

    /** Whether the holder paused as an admin, whose pause no one else replaces. */
    val pauseByAdmin = bool("pause_by_admin").nullable()

    /** Instant the write pause ends. */
    val pauseUntil = timestamp("pause_until").nullable()

    /** When an owner's signed `vault_deleted` ended the vault (`PROTOCOL.md` §12.3); `null` while it lives. */
    val deletedAt = timestamp("deleted_at").nullable()

    /** User who created the vault. */
    val createdByUserId = uuid("created_by_user_id")
        .references(
            IdentitiesTable.userId,
            onDelete = ReferenceOption.RESTRICT,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_vaults__created_by_user_id__identities",
        )
        .index("ix_vaults__created_by_user_id")

    /** Instant the vault was created. */
    val createdAt = timestamp("created_at")

    /** Primary key. */
    override val primaryKey: PrimaryKey = PrimaryKey(id, name = "pk_vaults")

    init {
        check("ck_vaults__log_head_hash_length") { SqlCondition("octet_length(log_head_hash) = 32") }
        check("ck_vaults__stored_section_count") { SqlCondition("stored_section_count >= live_section_count") }
        check("ck_vaults__pause_complete") {
            SqlCondition(
                "(pause_user_id is null and pause_by_admin is null and pause_until is null) or " +
                    "(pause_user_id is not null and pause_by_admin is not null and pause_until is not null)",
            )
        }
    }
}
