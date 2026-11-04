package dev.voir.cloak.server.section.persistence

import dev.voir.cloak.server.persistence.SqlCondition
import dev.voir.cloak.server.vault.persistence.VaultsTable
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.greaterEq

/**
 * Relational schema of `cloak.section_removals`: sections the host removed with their node, each
 * at the change number it took in its vault, so a client's change feed drops them
 * (`PROTOCOL.md` §15). The removed sections are no longer in `cloak.sections`.
 */
internal object SectionRemovalsTable : Table("cloak.section_removals") {
    /** Vault the section was in. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_section_removals__vault_id__vaults",
        )

    /** Change number the removal took in the vault. */
    val changeSeq = long("change_seq").check("ck_section_removals__change_seq") { it greaterEq 1L }

    /** Node of the removed section. */
    val nodeId = uuid("node_id")

    /** Name of the removed section. */
    val sectionName = varchar("section_name", 64)

    /** Primary key: one removal per change number of a vault. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, changeSeq, name = "pk_section_removals")

    init {
        check("ck_section_removals__section_name_format") { SqlCondition("section_name ~ '^[a-z][a-z0-9_]{0,63}$'") }
    }
}
