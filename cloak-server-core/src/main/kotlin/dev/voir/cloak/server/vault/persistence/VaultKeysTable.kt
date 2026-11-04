package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.vault_keys`: every key version of a vault with its commitment and,
 * after the first, the previous key wrapped by it (`PROTOCOL.md` §6).
 */
internal object VaultKeysTable : Table("cloak.vault_keys") {
    /** Vault; deleting it deletes its keys. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_vault_keys__vault_id__vaults",
        )

    /** Key version, from 1; `ck_vault_keys__previous_only_after_first` enforces it. */
    val version = integer("version")

    /** Commitment from the signed entry that created the version; 32 bytes. */
    val keyCommitment = binary("key_commitment")

    /** Key `version - 1` wrapped by this one; `null` for version 1. */
    val previousWrappedKey = binary("previous_wrapped_key").nullable()

    /** Instant the version was created. */
    val createdAt = timestamp("created_at")

    /** Primary key. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, version, name = "pk_vault_keys")

    init {
        check("ck_vault_keys__key_commitment_length") { SqlCondition("octet_length(key_commitment) = 32") }
        check("ck_vault_keys__previous_only_after_first") {
            SqlCondition(
                "(version = 1 and previous_wrapped_key is null) or " +
                    "(version > 1 and previous_wrapped_key is not null and octet_length(previous_wrapped_key) = 73)",
            )
        }
    }
}
