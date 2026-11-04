package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.core.isNull

/**
 * Relational schema of `cloak.checkpoint_leaves`: each section's leaf over a span of checkpoints
 * (`PROTOCOL.md` §7.5). A row belongs to the checkpoint of entry `s` when
 * `fromSeq <= s < untilSeq`, and to every later checkpoint while [untilSeq] is `null`. A checkpoint's
 * leaves are its rows ordered by `(nodeId, sectionName)` in byte order, which the `C` collation of
 * [sectionName] gives; positions are not stored.
 */
internal object CheckpointLeavesTable : Table("cloak.checkpoint_leaves") {
    /** Vault of the checkpoints. */
    val vaultId = uuid("vault_id")

    /** Node of the section. */
    val nodeId = uuid("node_id")

    /** Section name, compared byte for byte. */
    val sectionName = varchar("section_name", 64, collate = "C")

    /** Data version of the section's latest write. */
    val dataVersion = long("data_version").check("ck_checkpoint_leaves__data_version") { it greaterEq 1L }

    /** `writeHash` of that write; 32 bytes. */
    val writeHash = binary("write_hash")

    /** First checkpoint, by its log entry, that holds this leaf. */
    val fromSeq = long("from_seq")

    /** First later checkpoint that no longer holds it; `null` while every later one does. */
    val untilSeq = long("until_seq").nullable()

    /** Primary key: one span per section and first checkpoint. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, nodeId, sectionName, fromSeq, name = "pk_checkpoint_leaves")

    init {
        foreignKey(
            vaultId to VaultLogTable.vaultId,
            fromSeq to VaultLogTable.seq,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_checkpoint_leaves__vault_id_from_seq__vault_log",
        )
        foreignKey(
            vaultId to VaultLogTable.vaultId,
            untilSeq to VaultLogTable.seq,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_checkpoint_leaves__vault_id_until_seq__vault_log",
        )
        uniqueIndex(
            "uq_checkpoint_leaves__vault_id_node_id_section_name__open",
            vaultId,
            nodeId,
            sectionName,
            filterCondition = { untilSeq.isNull() },
        )
        check("ck_checkpoint_leaves__span") { SqlCondition("until_seq is null or until_seq > from_seq") }
        check("ck_checkpoint_leaves__write_hash_length") { SqlCondition("octet_length(write_hash) = 32") }
        check("ck_checkpoint_leaves__section_name_format") { SqlCondition("section_name ~ '^[a-z][a-z0-9_]{0,63}$'") }
    }
}
