package dev.voir.cloak.server.vault.domain

import dev.voir.cloak.server.identity.domain.UserId
import kotlinx.io.bytestring.ByteString

/**
 * An acceptance the caller signed with their current identity keys (`PROTOCOL.md` §9): a
 * `vaultAcceptance` of one vault or an `inviterAcceptance` of one person, as the request names.
 *
 * @property keyVersion The caller's current identity key version, whose signing key signed it.
 * @property signature The signature blob, `0x01` followed by the Ed25519 signature.
 */
public data class Acceptance(
    /** The caller's identity key version that signed. */
    public val keyVersion: Int,
    /** The signature blob. */
    public val signature: ByteString,
)

/**
 * The caller's signed acceptance of a vault as its view carries it (`PROTOCOL.md` §9, §12.4).
 *
 * @property inviterUserId `null` for the vault's own `vaultAcceptance`; otherwise the person who
 *   added the caller, whose `inviterAcceptance` this is.
 * @property keyVersion The caller's identity key version that signed it.
 * @property signature The signature blob.
 */
public data class VaultAcceptance(
    /** The inviter whose acceptance this is, or `null` for the vault's own. */
    public val inviterUserId: UserId?,
    /** The caller's identity key version that signed. */
    public val keyVersion: Int,
    /** The signature blob. */
    public val signature: ByteString,
)
