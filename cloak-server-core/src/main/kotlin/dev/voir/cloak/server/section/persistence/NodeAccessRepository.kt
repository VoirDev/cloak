package dev.voir.cloak.server.section.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.NodeShareNamesTable
import dev.voir.cloak.server.vault.persistence.NodeSharesTable
import dev.voir.cloak.server.vault.persistence.NodesTable
import dev.voir.cloak.server.vault.persistence.VaultMembersTable
import dev.voir.cloak.server.vault.persistence.VaultsTable
import org.jetbrains.exposed.v1.core.Column
import org.jetbrains.exposed.v1.core.JoinType
import org.jetbrains.exposed.v1.core.Op
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import kotlin.uuid.Uuid

/**
 * A vault where a user reads a node, as an accepted member of a vault no owner deleted
 * (`PROTOCOL.md` §7.7, §12.4).
 *
 * @property vaultId The vault.
 * @property role The user's role there.
 * @property home Whether it is the node's home, where the node was created.
 * @property createdSince In the home, the `seq` of its `node_created`, from which its sections are valid.
 * @property allSince For a share with `*`, the `seq` from which every name is shared.
 * @property names For a share by name, the `seq` from which each name is shared.
 * @property origin The node's owner, home and key as the creating or sharing entry recorded them.
 */
internal data class NodePlace(
    /** The vault. */
    val vaultId: VaultId,
    /** The user's role there. */
    val role: Role,
    /** Whether it is the node's home. */
    val home: Boolean,
    /** In the home, the `seq` of `node_created`. */
    val createdSince: Long?,
    /** For a share with `*`, from which `seq`. */
    val allSince: Long?,
    /** For a share by name, from which `seq` each name. */
    val names: Map<SectionName, Long>,
    /** The node's owner, home and key. */
    val origin: NodeOrigin,
) {
    /**
     * The `seq` from which a name may be read here, if it may.
     *
     * @param name Section name.
     * @return The `seq`, or `null`.
     */
    fun since(name: SectionName): Long? = if (home) createdSince else names[name] ?: allSince
}

/**
 * A stored section of a node: its vault, name and whether its latest write is a deletion.
 *
 * @property vaultId Vault.
 * @property sectionName Name.
 * @property deleted Whether the latest write is a deletion.
 */
internal data class StoredSection(
    /** Vault. */
    val vaultId: VaultId,
    /** Name. */
    val sectionName: SectionName,
    /** Whether the latest write is a deletion. */
    val deleted: Boolean,
)

/**
 * Queries by node across vaults, for the host's own checks and its purge. Every function runs
 * inside the caller's transaction; each is bounded by the user's vaults, the node's places or its
 * sections, through `pk_vault_members`, `ix_vault_members__user_id_accepted`, `pk_nodes`,
 * `ix_nodes__node_id`, `pk_node_shares`, `ix_node_shares__node_id` and `pk_sections`.
 */
internal object NodeAccessRepository {
    /**
     * Lists the nodes created in or shared into the vaults a user accepted and no owner deleted,
     * by node id.
     *
     * @param userId User.
     * @param after Node id the previous page ended at, or `null`.
     * @param limit Most nodes to return.
     * @return Node ids in order.
     */
    fun readableNodes(userId: UserId, after: NodeId?, limit: Int): List<NodeId> {
        val created = (NodesTable innerJoin VaultsTable)
            .join(VaultMembersTable, JoinType.INNER, additionalConstraint = { readable(userId, NodesTable.vaultId) })
            .select(NodesTable.nodeId)
            .withDistinct()
            .where { VaultsTable.deletedAt.isNull() and after(NodesTable.nodeId, after) }
            .orderBy(NodesTable.nodeId to SortOrder.ASC)
            .limit(limit)
            .map { NodeId(it[NodesTable.nodeId]) }
        val shared = (NodeSharesTable innerJoin VaultsTable)
            .join(VaultMembersTable, JoinType.INNER, additionalConstraint = { readable(userId, NodeSharesTable.vaultId) })
            .select(NodeSharesTable.nodeId)
            .withDistinct()
            .where { VaultsTable.deletedAt.isNull() and after(NodeSharesTable.nodeId, after) }
            .orderBy(NodeSharesTable.nodeId to SortOrder.ASC)
            .limit(limit)
            .map { NodeId(it[NodeSharesTable.nodeId]) }
        // Each query is a keyset page in the database (`node_id > after`, ordered, limited), so
        // this merges at most twice [limit] ids; both are sorted, so the first [limit] of their
        // union are a correct page. Lowercase UUID text orders as PostgreSQL orders the bytes.
        return (created + shared).distinct().sortedBy { it.value.toString() }.take(limit)
    }

    /**
     * Lists the vaults where a user reads a node: its home, if the node was created there, and the
     * vaults it is shared into; only vaults the user accepted and no owner deleted.
     *
     * @param userId User.
     * @param nodeId Node.
     * @return The places, by vault.
     */
    fun places(userId: UserId, nodeId: NodeId): List<NodePlace> {
        val homes = (NodesTable innerJoin VaultsTable)
            .join(VaultMembersTable, JoinType.INNER, additionalConstraint = { readable(userId, NodesTable.vaultId) })
            .select(NodesTable.vaultId, NodesTable.ownerUserId, NodesTable.nodeKey, NodesTable.createdSeq, VaultMembersTable.role)
            .where { (NodesTable.nodeId eq nodeId.value) and VaultsTable.deletedAt.isNull() }
            .map {
                val vaultId = VaultId(it[NodesTable.vaultId])
                NodePlace(
                    vaultId,
                    Role.fromCode(it[VaultMembersTable.role]),
                    home = true,
                    createdSince = it[NodesTable.createdSeq],
                    allSince = null,
                    names = emptyMap(),
                    origin = NodeOrigin(UserId(it[NodesTable.ownerUserId]), vaultId, NodeKey(it[NodesTable.nodeKey])),
                )
            }
        val shares = (NodeSharesTable innerJoin VaultsTable)
            .join(VaultMembersTable, JoinType.INNER, additionalConstraint = { readable(userId, NodeSharesTable.vaultId) })
            .select(
                NodeSharesTable.vaultId,
                NodeSharesTable.ownerUserId,
                NodeSharesTable.homeVaultId,
                NodeSharesTable.nodeKey,
                NodeSharesTable.allSince,
                VaultMembersTable.role,
            )
            .where { (NodeSharesTable.nodeId eq nodeId.value) and VaultsTable.deletedAt.isNull() }
            .map {
                val vaultId = VaultId(it[NodeSharesTable.vaultId])
                val names = NodeShareNamesTable.select(NodeShareNamesTable.sectionName, NodeShareNamesTable.since)
                    .where { (NodeShareNamesTable.vaultId eq vaultId.value) and (NodeShareNamesTable.nodeId eq nodeId.value) }
                    .associate { row -> SectionName(row[NodeShareNamesTable.sectionName]) to row[NodeShareNamesTable.since] }
                NodePlace(
                    vaultId,
                    Role.fromCode(it[VaultMembersTable.role]),
                    home = false,
                    createdSince = null,
                    allSince = it[NodeSharesTable.allSince],
                    names = names,
                    origin = NodeOrigin(
                        UserId(it[NodeSharesTable.ownerUserId]),
                        VaultId(it[NodeSharesTable.homeVaultId]),
                        NodeKey(it[NodeSharesTable.nodeKey]),
                    ),
                )
            }
        return (homes + shares).sortedBy { it.vaultId.value.toString() }
    }

    /**
     * Lists the live sections of a node in one vault that stand by rule 6 (`PROTOCOL.md` §8.4):
     * written with the origin the place recorded, under a name it lets be read, since no later than
     * the write's head.
     *
     * @param nodeId Node.
     * @param place Where the user reads the node.
     * @return Section names.
     */
    fun readableSections(nodeId: NodeId, place: NodePlace): List<SectionName> =
        SectionsTable.select(
            SectionsTable.sectionName,
            SectionsTable.logSeq,
            SectionsTable.homeVaultId,
            SectionsTable.ownerUserId,
            SectionsTable.nodeKey,
        )
            .where {
                (SectionsTable.vaultId eq place.vaultId.value) and (SectionsTable.nodeId eq nodeId.value) and (SectionsTable.deleted eq false)
            }
            .orderBy(SectionsTable.sectionName to SortOrder.ASC)
            .mapNotNull { row ->
                val name = SectionName(row[SectionsTable.sectionName])
                val since = place.since(name)
                val sameOrigin = row[SectionsTable.homeVaultId] == place.origin.homeVaultId.value &&
                    row[SectionsTable.ownerUserId] == place.origin.ownerUserId.value &&
                    row[SectionsTable.nodeKey] == place.origin.nodeKey.value
                name.takeIf { sameOrigin && since != null && since <= row[SectionsTable.logSeq] }
            }

    /** A membership of [userId] in the vault [vaultColumn] names that they accepted. */
    private fun readable(userId: UserId, vaultColumn: Column<Uuid>): Op<Boolean> =
        (VaultMembersTable.vaultId eq vaultColumn) and (VaultMembersTable.userId eq userId.value) and
            (VaultMembersTable.accepted eq true) and (VaultsTable.id eq vaultColumn)

    /** Node ids after [after], or every one. */
    private fun after(column: Column<Uuid>, after: NodeId?): Op<Boolean> =
        if (after == null) Op.TRUE else column greater after.value

    /**
     * Lists every stored section of a node, live and deleted, in every vault.
     *
     * @param nodeId Node.
     * @return Sections.
     */
    fun storedSections(nodeId: NodeId): List<StoredSection> =
        SectionsTable.select(SectionsTable.vaultId, SectionsTable.sectionName, SectionsTable.deleted)
            .where { SectionsTable.nodeId eq nodeId.value }
            .map { StoredSection(VaultId(it[SectionsTable.vaultId]), SectionName(it[SectionsTable.sectionName]), it[SectionsTable.deleted]) }

    /**
     * Deletes every stored section of a node in one vault.
     *
     * @param vaultId Vault.
     * @param nodeId Node.
     */
    fun deleteNode(vaultId: VaultId, nodeId: NodeId) {
        SectionsTable.deleteWhere { (SectionsTable.vaultId eq vaultId.value) and (SectionsTable.nodeId eq nodeId.value) }
    }

    /**
     * Records a removed section at its change number.
     *
     * @param vaultId Vault.
     * @param changeSeq Change number the removal takes.
     * @param nodeId Node.
     * @param sectionName Section name.
     */
    fun recordRemoval(vaultId: VaultId, changeSeq: Long, nodeId: NodeId, sectionName: SectionName) {
        SectionRemovalsTable.insert {
            it[SectionRemovalsTable.vaultId] = vaultId.value
            it[SectionRemovalsTable.changeSeq] = changeSeq
            it[SectionRemovalsTable.nodeId] = nodeId.value
            it[SectionRemovalsTable.sectionName] = sectionName.value
        }
    }
}
