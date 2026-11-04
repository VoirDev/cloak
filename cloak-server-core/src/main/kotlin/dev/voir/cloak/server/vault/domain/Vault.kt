package dev.voir.cloak.server.vault.domain

import dev.voir.cloak.server.identity.domain.UserId
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A vault as the server describes it to a member. Clients trust none of it until it matches the
 * verified log.
 *
 * @property id The vault.
 * @property role The caller's role.
 * @property keyVersion Current vault key version.
 * @property keyEnvelope The caller's envelope of the current key; `null` while it awaits delivery.
 * @property envelopeUserKeyVersion The caller's key version the envelope is sealed to; `null` with it.
 * @property logSeq `seq` of the last log entry.
 * @property logHeadHash `entryHash` of the last log entry.
 * @property createdByUserId Creator.
 * @property createdAt Creation instant.
 * @property accepted Whether the caller accepted the vault (`PROTOCOL.md` §12.4); unsigned.
 * @property addedByUserId Who added the caller, per the log; `null` for the vault's creator.
 * @property deleted Whether the log ends in `vault_deleted`: only the log and member list remain.
 */
public data class Vault(
    /** The vault. */
    public val id: VaultId,
    /** The caller's role. */
    public val role: Role,
    /** Current vault key version. */
    public val keyVersion: Int,
    /** The caller's envelope of the current key. */
    public val keyEnvelope: ByteString?,
    /** The caller's key version the envelope is sealed to. */
    public val envelopeUserKeyVersion: Int?,
    /** `seq` of the last log entry. */
    public val logSeq: Long,
    /** `entryHash` of the last log entry. */
    public val logHeadHash: ByteString,
    /** Creator. */
    public val createdByUserId: UserId,
    /** Creation instant. */
    public val createdAt: Instant,
    /** Whether the caller accepted the vault. */
    public val accepted: Boolean = true,
    /** Who added the caller. */
    public val addedByUserId: UserId? = null,
    /** Whether an owner deleted the vault. */
    public val deleted: Boolean = false,
)

/**
 * One key version of a vault.
 *
 * @property version Key version.
 * @property previousWrappedKey The previous version wrapped by this one; `null` for version 1.
 * @property createdAt Creation instant.
 */
public data class VaultKey(
    /** Key version. */
    public val version: Int,
    /** The previous version wrapped by this one. */
    public val previousWrappedKey: ByteString?,
    /** Creation instant. */
    public val createdAt: Instant,
)
