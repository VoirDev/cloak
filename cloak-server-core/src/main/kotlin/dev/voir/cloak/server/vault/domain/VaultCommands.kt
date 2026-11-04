package dev.voir.cloak.server.vault.domain

import dev.voir.cloak.server.identity.domain.UserId
import kotlinx.io.bytestring.ByteString

/**
 * Creates a vault with the caller as owner.
 *
 * @property id Client-generated vault id.
 * @property keyEnvelope Key version 1 sealed to the caller's current keys.
 * @property log The signed `vault_created` entry.
 */
public data class CreateVaultCommand(
    /** Client-generated vault id. */
    public val id: VaultId,
    /** Key version 1 sealed to the caller. */
    public val keyEnvelope: ByteString,
    /** The signed `vault_created` entry. */
    public val log: LogEntryInput,
)

/**
 * Adds a member.
 *
 * @property userId User to add.
 * @property role Their role.
 * @property keyVersion The vault's current key version, which the envelope holds.
 * @property userKeyVersion The user's key version the envelope is sealed to.
 * @property keyEnvelope The current vault key sealed to the user.
 * @property log The signed `member_added` entry.
 */
public data class AddMemberCommand(
    /** User to add. */
    public val userId: UserId,
    /** Their role. */
    public val role: Role,
    /** The vault's current key version. */
    public val keyVersion: Int,
    /** The user's key version the envelope is sealed to. */
    public val userKeyVersion: Int,
    /** The current vault key sealed to the user. */
    public val keyEnvelope: ByteString,
    /** The signed `member_added` entry. */
    public val log: LogEntryInput,
)

/**
 * Changes a member's role.
 *
 * @property role The new role.
 * @property log The signed `member_role_set` entry.
 * @property leftOut Latest writes the entry's checkpoint leaves out.
 */
public data class SetMemberRoleCommand(
    /** The new role. */
    public val role: Role,
    /** The signed `member_role_set` entry. */
    public val log: LogEntryInput,
    /** Writes the checkpoint leaves out. */
    public val leftOut: List<LeftOutWrite> = emptyList(),
)

/**
 * Stores a new envelope of the current vault key for a member (`PROTOCOL.md` §6.3).
 *
 * @property keyVersion The vault's current key version.
 * @property userKeyVersion The member's committed key version.
 * @property keyEnvelope The current vault key sealed to it.
 */
public data class DeliverEnvelopeCommand(
    /** The vault's current key version. */
    public val keyVersion: Int,
    /** The member's committed key version. */
    public val userKeyVersion: Int,
    /** The envelope. */
    public val keyEnvelope: ByteString,
)

/**
 * The caller leaves a vault.
 *
 * @property log The signed `member_removed` with the caller as subject.
 * @property leftOut Latest writes the entry's checkpoint leaves out.
 */
public data class LeaveVaultCommand(
    /** The signed `member_removed`. */
    public val log: LogEntryInput,
    /** Writes the checkpoint leaves out. */
    public val leftOut: List<LeftOutWrite> = emptyList(),
)

/**
 * A member's envelope in a rotation.
 *
 * @property userId The member.
 * @property userKeyVersion Their committed key version.
 * @property keyEnvelope The new vault key sealed to it.
 */
public data class MemberEnvelope(
    /** The member. */
    public val userId: UserId,
    /** Their committed key version. */
    public val userKeyVersion: Int,
    /** The new vault key sealed to it. */
    public val keyEnvelope: ByteString,
)

/**
 * Rotates the vault key, removing members (`PROTOCOL.md` §7.4).
 *
 * @property keyVersion The new key version.
 * @property previousWrappedKey The current key wrapped by the new one.
 * @property envelopes The new key for every remaining member whose key version is not superseded.
 * @property log Zero or more `member_removed`, then `key_rotated`.
 * @property leftOut Latest writes the checkpoint leaves out.
 */
public data class RotateVaultCommand(
    /** The new key version. */
    public val keyVersion: Int,
    /** The current key wrapped by the new one. */
    public val previousWrappedKey: ByteString,
    /** Envelopes of the new key. */
    public val envelopes: List<MemberEnvelope>,
    /** The request's entries. */
    public val log: List<LogEntryInput>,
    /** Writes the checkpoint leaves out. */
    public val leftOut: List<LeftOutWrite> = emptyList(),
)

/**
 * Records the caller's key replacement in a vault (`PROTOCOL.md` §5.6).
 *
 * @property log The signed `member_keys_replaced`.
 * @property keyEnvelope The current vault key sealed to the caller's new keys; `null` when the
 *   caller does not hold it, for an admin to deliver.
 * @property leftOut Latest writes the checkpoint leaves out.
 */
public data class RecordKeyReplacementCommand(
    /** The signed `member_keys_replaced`. */
    public val log: LogEntryInput,
    /** The current vault key sealed to the new keys, or `null`. */
    public val keyEnvelope: ByteString?,
    /** Writes the checkpoint leaves out. */
    public val leftOut: List<LeftOutWrite> = emptyList(),
)

/**
 * One rotation of a batch (`POST /rotations/batch-apply`).
 *
 * @property vaultId The vault rotated.
 * @property command Its rotation, exactly as `rotateVault` takes it.
 */
public data class VaultRotation(
    /** The vault rotated. */
    public val vaultId: VaultId,
    /** Its rotation. */
    public val command: RotateVaultCommand,
)
