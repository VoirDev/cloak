package dev.voir.cloak.server.section.domain

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.protocol.Canonical
import dev.voir.cloak.server.vault.domain.VaultId

/**
 * Who created a node, where it lives and the application's key for it (`PROTOCOL.md` §8.1).
 *
 * @property ownerUserId The node's owner, who created it.
 * @property homeVaultId The node's home vault.
 * @property nodeKey The application's key for the node.
 */
public data class NodeOrigin(
    /** The node's owner, who created it. */
    public val ownerUserId: UserId,
    /** The node's home vault. */
    public val homeVaultId: VaultId,
    /** The application's key for the node. */
    public val nodeKey: NodeKey,
) {
    /**
     * The node's id: `UUIDv5(ownerUserId, label "cloak/v1/node" ‖ uuid homeVaultId ‖ str nodeKey)`.
     */
    public val nodeId: NodeId
        get() = NodeId(
            UserId.uuidV5(
                ownerUserId.value,
                Canonical().label("cloak/v1/node").uuid(homeVaultId.value).str(nodeKey.value).build().toByteArray(),
            ),
        )
}
