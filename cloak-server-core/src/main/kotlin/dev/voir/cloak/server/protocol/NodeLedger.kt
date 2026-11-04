package dev.voir.cloak.server.protocol

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.VaultId

/**
 * A node created in a vault, its home (`PROTOCOL.md` §7.7).
 *
 * @property ownerUserId The node's owner, who created it.
 * @property nodeKey The node's key.
 * @property seq The `seq` of `node_created`; the node's sections are valid in its home from there.
 */
internal data class CreatedNode(
    /** The node's owner. */
    val ownerUserId: UserId,
    /** The node's key. */
    val nodeKey: NodeKey,
    /** The `seq` of `node_created`. */
    val seq: Long,
)

/**
 * A node shared into a vault from its home (`PROTOCOL.md` §7.7).
 *
 * @property ownerUserId The node's owner, who shared it.
 * @property homeVaultId The node's home vault.
 * @property nodeKey The node's key.
 * @property all The `seq` from which every name is shared, when shared with `*`.
 * @property names The `seq` from which each name shared by name is shared.
 */
internal data class NodeShare(
    /** The node's owner. */
    val ownerUserId: UserId,
    /** The node's home vault. */
    val homeVaultId: VaultId,
    /** The node's key. */
    val nodeKey: NodeKey,
    /** The `seq` from which every name is shared. */
    val all: Long?,
    /** The `seq` from which each name is shared. */
    val names: Map<SectionName, Long>,
) {
    /**
     * The `seq` from which a name is shared, if it is.
     *
     * @param name Section name.
     * @return The `seq`, or `null`.
     */
    fun since(name: SectionName): Long? = names[name] ?: all
}

/** Where the nodes of one vault's log already stand: stored state, or none for a new vault. */
internal interface NodeLookup {
    /**
     * The node created in the vault with this id, if any.
     *
     * @param nodeId Node.
     * @return The node, or `null`.
     */
    fun created(nodeId: NodeId): CreatedNode?

    /**
     * The share of a node into the vault, if any.
     *
     * @param nodeId Node.
     * @return The share, or `null`.
     */
    fun share(nodeId: NodeId): NodeShare?

    /**
     * Nodes a user shared into the vault.
     *
     * @param ownerUserId The owner.
     * @return Their nodes.
     */
    fun sharesOwnedBy(ownerUserId: UserId): Set<NodeId>

    /** A vault with no nodes. */
    object Empty : NodeLookup {
        override fun created(nodeId: NodeId): CreatedNode? = null

        override fun share(nodeId: NodeId): NodeShare? = null

        override fun sharesOwnedBy(ownerUserId: UserId): Set<NodeId> = emptySet()
    }
}

/**
 * A vault's nodes as a request leaves them: what [base] stores, changed by the request's entries.
 * Only the changes are held, so a vault with many nodes is never loaded whole.
 *
 * @property base Stored state.
 * @property created Nodes the request created.
 * @property shares Shares the request set or, with `null`, ended.
 */
internal data class NodeLedger(
    /** Stored state. */
    val base: NodeLookup = NodeLookup.Empty,
    /** Nodes the request created. */
    val created: Map<NodeId, CreatedNode> = emptyMap(),
    /** Shares the request set or ended. */
    val shares: Map<NodeId, NodeShare?> = emptyMap(),
) {
    /**
     * The node created in the vault with this id.
     *
     * @param nodeId Node.
     * @return The node, or `null`.
     */
    fun createdNode(nodeId: NodeId): CreatedNode? = created[nodeId] ?: base.created(nodeId)

    /**
     * The share of a node into the vault now.
     *
     * @param nodeId Node.
     * @return The share, or `null`.
     */
    fun share(nodeId: NodeId): NodeShare? = if (nodeId in shares) shares[nodeId] else base.share(nodeId)

    /**
     * Records a created node.
     *
     * @param nodeId Node.
     * @param node What `node_created` recorded.
     * @return The changed ledger.
     */
    fun withCreated(nodeId: NodeId, node: CreatedNode): NodeLedger = copy(created = created + (nodeId to node))

    /**
     * Sets or ends a share.
     *
     * @param nodeId Node.
     * @param share The share, or `null` to end it.
     * @return The changed ledger.
     */
    fun withShare(nodeId: NodeId, share: NodeShare?): NodeLedger = copy(shares = shares + (nodeId to share))

    /**
     * Ends every share of an owner who stops being a member (§7.7).
     *
     * @param ownerUserId The owner.
     * @return The changed ledger.
     */
    fun withoutSharesOf(ownerUserId: UserId): NodeLedger {
        val owned = base.sharesOwnedBy(ownerUserId) + shares.filterValues { it?.ownerUserId == ownerUserId }.keys
        return copy(shares = shares + owned.associateWith { null })
    }
}
