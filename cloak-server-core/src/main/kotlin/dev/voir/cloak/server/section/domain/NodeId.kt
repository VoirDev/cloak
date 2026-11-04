package dev.voir.cloak.server.section.domain

import kotlin.uuid.Uuid

/**
 * Identifier of a node: a record made of sections, which may live in different vaults.
 *
 * Clients generate it before upload, because it is bound into each section's associated data
 * and signature.
 */
@JvmInline
public value class NodeId(
    /** Client-generated UUID, unique across the server. */
    public val value: Uuid,
)
