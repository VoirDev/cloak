package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.nodes`: the nodes created in a vault, their home, by the owner's
 * signed `node_created` (`PROTOCOL.md` §7.7).
 */
internal object NodesTable : Table("cloak.nodes") {
    /** The home vault; deleting it deletes its nodes. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_nodes__vault_id__vaults",
        )

    /** The node. */
    val nodeId = uuid("node_id")

    /** The node's owner, who created it. */
    val ownerUserId = uuid("owner_user_id")

    /** The node's key. */
    val nodeKey = varchar("node_key", 255)

    /** The `seq` of `node_created`; the node's sections are valid here from it on. */
    val createdSeq = long("created_seq").check("ck_nodes__created_seq") { it greaterEq 2L }

    /** Primary key: a node is created in its home once. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, nodeId, name = "pk_nodes")

    init {
        // A node's homes, for the host's checks and purges by node id.
        index("ix_nodes__node_id", false, nodeId)
    }
}

/**
 * Relational schema of `cloak.node_shares`: nodes shared into a vault from their home, as the log
 * leaves them (`PROTOCOL.md` §7.7).
 */
internal object NodeSharesTable : Table("cloak.node_shares") {
    /** The vault the node is shared into; deleting it deletes its shares. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_node_shares__vault_id__vaults",
        )

    /** The node. */
    val nodeId = uuid("node_id")

    /** The node's owner, who shared it. */
    val ownerUserId = uuid("owner_user_id")

    /** The node's home vault. */
    val homeVaultId = uuid("home_vault_id")

    /** The node's key. */
    val nodeKey = varchar("node_key", 255)

    /** The `seq` from which every name is shared, when shared with `*`. */
    val allSince = long("all_since").nullable()

    /** Primary key: one share per vault and node. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, nodeId, name = "pk_node_shares")

    init {
        index("ix_node_shares__vault_id_owner_user_id", false, vaultId, ownerUserId)
        // The vaults a node is shared into, for the host's checks by node id.
        index("ix_node_shares__node_id", false, nodeId)
        check("ck_node_shares__home_elsewhere") { SqlCondition("home_vault_id <> vault_id") }
    }
}

/** Relational schema of `cloak.node_share_names`: names shared by name, each from its `seq`. */
internal object NodeShareNamesTable : Table("cloak.node_share_names") {
    /** The vault the node is shared into. */
    val vaultId = uuid("vault_id")

    /** The node. */
    val nodeId = uuid("node_id")

    /** A shared name. */
    val sectionName = varchar("section_name", 64)

    /** The `seq` from which it is shared. */
    val since = long("since")

    /** Primary key: one row per shared name. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, nodeId, sectionName, name = "pk_node_share_names")

    init {
        foreignKey(
            vaultId to NodeSharesTable.vaultId,
            nodeId to NodeSharesTable.nodeId,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_node_share_names__vault_id_node_id__node_shares",
        )
        check("ck_node_share_names__section_name_format") { SqlCondition("section_name ~ '^[a-z][a-z0-9_]{0,63}$'") }
    }
}

/**
 * Relational schema of `cloak.accepted_inviters`: people whose every vault a user accepts, now and
 * later (`PROTOCOL.md` §12.4).
 */
internal object AcceptedInvitersTable : Table("cloak.accepted_inviters") {
    /** The user who accepts. */
    val userId = uuid("user_id")

    /** The person whose vaults they accept. */
    val inviterUserId = uuid("inviter_user_id")

    /** When they accepted. */
    val acceptedAt = timestamp("accepted_at")

    /** Primary key: one acceptance per pair. */
    override val primaryKey: PrimaryKey = PrimaryKey(userId, inviterUserId, name = "pk_accepted_inviters")
}
