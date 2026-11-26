package dev.voir.cloak.server.section.domain

import kotlin.uuid.Uuid

/**
 * Identifier of a node: a record made of sections, which may live in different vaults.
 *
 * It is derived, never chosen: `UUIDv5(ownerUserId, label "cloak/v1/node" ‖ uuid homeVaultId ‖
 * str nodeKey)` (`PROTOCOL.md` §8.1, [NodeOrigin.nodeId]), so nobody can claim another user's node.
 * It is bound into each section's associated data and signature.
 */
@JvmInline
public value class NodeId(
    /** The UUID derived from the node's origin. */
    public val value: Uuid,
)
