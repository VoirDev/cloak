package dev.voir.cloak.server.vault.domain

import kotlin.uuid.Uuid

/**
 * Identifier of a vault.
 *
 * Clients generate it before upload, because it is bound into key envelopes, section
 * content and log entries.
 */
@JvmInline
public value class VaultId(
    /** Client-generated UUID. */
    public val value: Uuid,
)
