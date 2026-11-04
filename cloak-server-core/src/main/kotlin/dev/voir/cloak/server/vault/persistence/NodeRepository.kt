package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.protocol.CreatedNode
import dev.voir.cloak.server.protocol.NodeLedger
import dev.voir.cloak.server.protocol.NodeLookup
import dev.voir.cloak.server.protocol.NodeShare
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.VaultId
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll

/**
 * Reads and writes where nodes live (`cloak.nodes`, `cloak.node_shares`, `cloak.node_share_names`,
 * `PROTOCOL.md` §7.7), as the vault log leaves it. Every function runs inside the caller's
 * transaction, which holds the vault's lock whenever it writes.
 */
internal object NodeRepository {
    /**
     * The stored nodes of one vault, looked up one node at a time, so a vault with many nodes is
     * never loaded whole.
     *
     * @param vaultId The vault.
     * @return The lookup.
     */
    fun lookup(vaultId: VaultId): NodeLookup = object : NodeLookup {
        override fun created(nodeId: NodeId): CreatedNode? = createdNode(vaultId, nodeId)

        override fun share(nodeId: NodeId): NodeShare? = share(vaultId, nodeId)

        override fun sharesOwnedBy(ownerUserId: UserId): Set<NodeId> =
            NodeSharesTable.select(NodeSharesTable.nodeId)
                .where { (NodeSharesTable.vaultId eq vaultId.value) and (NodeSharesTable.ownerUserId eq ownerUserId.value) }
                .map { NodeId(it[NodeSharesTable.nodeId]) }
                .toSet()
    }

    /**
     * The node created in a vault, its home.
     *
     * @param vaultId The vault.
     * @param nodeId The node.
     * @return The node, or `null`.
     */
    fun createdNode(vaultId: VaultId, nodeId: NodeId): CreatedNode? =
        NodesTable.selectAll()
            .where { (NodesTable.vaultId eq vaultId.value) and (NodesTable.nodeId eq nodeId.value) }
            .singleOrNull()
            ?.let {
                CreatedNode(UserId(it[NodesTable.ownerUserId]), NodeKey(it[NodesTable.nodeKey]), it[NodesTable.createdSeq])
            }

    /**
     * The share of a node into a vault.
     *
     * @param vaultId The vault.
     * @param nodeId The node.
     * @return The share, or `null`.
     */
    fun share(vaultId: VaultId, nodeId: NodeId): NodeShare? {
        val row = NodeSharesTable.selectAll()
            .where { (NodeSharesTable.vaultId eq vaultId.value) and (NodeSharesTable.nodeId eq nodeId.value) }
            .singleOrNull() ?: return null
        val names = NodeShareNamesTable.selectAll()
            .where { (NodeShareNamesTable.vaultId eq vaultId.value) and (NodeShareNamesTable.nodeId eq nodeId.value) }
            .associate { SectionName(it[NodeShareNamesTable.sectionName]) to it[NodeShareNamesTable.since] }
        return NodeShare(
            ownerUserId = UserId(row[NodeSharesTable.ownerUserId]),
            homeVaultId = VaultId(row[NodeSharesTable.homeVaultId]),
            nodeKey = NodeKey(row[NodeSharesTable.nodeKey]),
            all = row[NodeSharesTable.allSince],
            names = names,
        )
    }

    /**
     * Stores what a request changed of a vault's nodes.
     *
     * @param vaultId The vault, locked.
     * @param ledger The vault's nodes after the request.
     */
    fun store(vaultId: VaultId, ledger: NodeLedger) {
        for ((nodeId, node) in ledger.created) {
            NodesTable.insert {
                it[NodesTable.vaultId] = vaultId.value
                it[NodesTable.nodeId] = nodeId.value
                it[ownerUserId] = node.ownerUserId.value
                it[nodeKey] = node.nodeKey.value
                it[createdSeq] = node.seq
            }
        }
        for ((nodeId, share) in ledger.shares) {
            NodeSharesTable.deleteWhere { (NodeSharesTable.vaultId eq vaultId.value) and (NodeSharesTable.nodeId eq nodeId.value) }
            if (share == null) continue
            NodeSharesTable.insert {
                it[NodeSharesTable.vaultId] = vaultId.value
                it[NodeSharesTable.nodeId] = nodeId.value
                it[ownerUserId] = share.ownerUserId.value
                it[homeVaultId] = share.homeVaultId.value
                it[nodeKey] = share.nodeKey.value
                it[allSince] = share.all
            }
            NodeShareNamesTable.batchInsert(share.names.entries) { (name, since) ->
                this[NodeShareNamesTable.vaultId] = vaultId.value
                this[NodeShareNamesTable.nodeId] = nodeId.value
                this[NodeShareNamesTable.sectionName] = name.value
                this[NodeShareNamesTable.since] = since
            }
        }
    }
}
