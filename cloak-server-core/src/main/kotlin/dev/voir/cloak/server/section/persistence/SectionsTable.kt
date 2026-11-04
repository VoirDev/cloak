package dev.voir.cloak.server.section.persistence

import dev.voir.cloak.server.identity.persistence.IdentityKeysTable
import dev.voir.cloak.server.persistence.SqlCondition
import dev.voir.cloak.server.vault.persistence.VaultKeysTable
import dev.voir.cloak.server.vault.persistence.VaultsTable
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.sections`: the latest signed write of every section, deletions
 * included (`PROTOCOL.md` §8). A section is `(vault_id, node_id, section_name)`.
 */
internal object SectionsTable : Table("cloak.sections") {
    /** Vault the section lives in; deleting it deletes its sections. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_sections__vault_id__vaults",
        )

    /** Node of the section. */
    val nodeId = uuid("node_id").index("ix_sections__node_id")

    /** Section name. */
    val sectionName = varchar("section_name", 64)

    /** App-defined node type, as the write signs it. */
    val nodeType = varchar("node_type", 64)

    /** The node's home vault, signed with every write (`PROTOCOL.md` §8.1). */
    val homeVaultId = uuid("home_vault_id")

    /** The node's owner, signed with every write. */
    val ownerUserId = uuid("owner_user_id")

    /** The node's key, signed with every write. */
    val nodeKey = varchar("node_key", 255)

    /** Vault key version that encrypts the content. */
    val vaultKeyVersion = integer("vault_key_version")

    /** Data version of the write. */
    val dataVersion = long("data_version").check("ck_sections__data_version") { it greaterEq 1L }

    /** Whether the write deletes the section. */
    val deleted = bool("deleted")

    /** Log head the writer cited. */
    val logSeq = long("log_seq").check("ck_sections__log_seq") { it greaterEq 1L }

    /** `entryHash` of that head; 32 bytes. */
    val logHeadHash = binary("log_head_hash")

    /** `writeHash` of the previous write; `null` for the first. */
    val previousWriteHash = binary("previous_write_hash").nullable()

    /** Writer. */
    val writerUserId = uuid("writer_user_id")

    /** The writer's identity key version that signed. */
    val writerKeyVersion = integer("writer_key_version")

    /** Section ciphertext; `null` for a deletion. */
    val ciphertext = binary("ciphertext").nullable()

    /** SHA-256 of the ciphertext, the digest the write signs; `null` for a deletion. */
    val ciphertextHash = binary("ciphertext_hash").nullable()

    /** Writer's signature. */
    val signature = binary("signature")

    /** SHA-256 of the write's signed message; 32 bytes. */
    val writeHash = binary("write_hash")

    /** Change number of the write within its vault. */
    val changeSeq = long("change_seq").check("ck_sections__change_seq") { it greaterEq 1L }

    /** Instant the write was stored. */
    val writtenAt = timestamp("written_at")

    /** Primary key: one row per section. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, nodeId, sectionName, name = "pk_sections")

    init {
        foreignKey(
            vaultId to VaultKeysTable.vaultId,
            vaultKeyVersion to VaultKeysTable.version,
            onDelete = ReferenceOption.NO_ACTION,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_sections__vault_id_vault_key_version__vault_keys",
        )
        foreignKey(
            writerUserId to IdentityKeysTable.userId,
            writerKeyVersion to IdentityKeysTable.keyVersion,
            onDelete = ReferenceOption.RESTRICT,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_sections__writer_user_id_writer_key_version__identity_keys",
        )
        uniqueIndex("uq_sections__vault_id_change_seq", vaultId, changeSeq)
        index("ix_sections__writer_user_id_writer_key_version", false, writerUserId, writerKeyVersion)
        check("ck_sections__section_name_format") { SqlCondition("section_name ~ '^[a-z][a-z0-9_]{0,63}$'") }
        check("ck_sections__node_type_format") { SqlCondition("node_type ~ '^[a-z][a-z0-9_.-]{0,63}$'") }
        check("ck_sections__log_head_hash_length") { SqlCondition("octet_length(log_head_hash) = 32") }
        check("ck_sections__previous_write_hash") {
            SqlCondition(
                "(data_version = 1 and previous_write_hash is null) or " +
                    "(data_version > 1 and previous_write_hash is not null and octet_length(previous_write_hash) = 32)",
            )
        }
        check("ck_sections__deleted_has_no_ciphertext") { SqlCondition("deleted = (ciphertext is null)") }
        check("ck_sections__ciphertext_size") {
            SqlCondition(
                "ciphertext is null or (octet_length(ciphertext) between 297 and 1048576 and " +
                    "(octet_length(ciphertext) - 41) % 256 = 0)",
            )
        }
        check("ck_sections__ciphertext_hash") {
            SqlCondition(
                "(ciphertext is null and ciphertext_hash is null) or " +
                    "(ciphertext is not null and ciphertext_hash is not null and octet_length(ciphertext_hash) = 32)",
            )
        }
        check("ck_sections__signature_length") { SqlCondition("octet_length(signature) = 65") }
        check("ck_sections__write_hash_length") { SqlCondition("octet_length(write_hash) = 32") }
    }
}
