package dev.voir.cloak.server.vault

import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.Vault
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.MemberRow
import dev.voir.cloak.server.vault.persistence.VaultRepository
import dev.voir.cloak.server.vault.persistence.VaultRow

/**
 * A vault as one request sees it, with the caller's membership.
 *
 * @property vault The vault.
 * @property members Every member, by user.
 * @property caller The caller's membership.
 */
internal data class VaultView(
    /** The vault. */
    val vault: VaultRow,
    /** Every member, by user. */
    val members: Map<UserId, MemberRow>,
    /** The caller's membership. */
    val caller: MemberRow,
) {
    /**
     * Requires the caller to hold a role.
     *
     * @param needed The weakest role that may act.
     * @param action What the caller tried, for the detail.
     * @throws CloakException `role_required` otherwise.
     */
    fun requireRole(needed: Role, action: String) {
        if (!caller.membership.role.includes(needed)) throw CloakException.roleRequired(needed, action)
    }
}

/** How operations reach a vault: hidden unless the caller is a member (`not_found`, never `403`). */
internal object VaultAccess {
    /**
     * Locks a vault for the rest of the transaction and loads it with its members.
     *
     * @param caller The caller.
     * @param vaultId The vault.
     * @return The vault as the caller sees it.
     * @throws CloakException `not_found` when it does not exist or the caller is not a member.
     */
    fun lockForMember(caller: UserId, vaultId: VaultId): VaultView {
        // Check membership before taking the lock, so a non-member cannot hold another's vault
        // locked or time its answers; check again under the lock, which is what counts.
        MemberRepository.find(vaultId, caller) ?: throw CloakException.notFound("vault")
        val vault = VaultRepository.lock(listOf(vaultId))[vaultId] ?: throw CloakException.notFound("vault")
        // A deleted vault takes no more changes (`PROTOCOL.md` §12.3).
        if (vault.isDeleted) throw CloakException.notFound("vault")
        val members = MemberRepository.all(vaultId)
        val membership = members[caller] ?: throw CloakException.notFound("vault")
        return VaultView(vault, members, membership)
    }

    /**
     * Loads a vault for reading, without a lock.
     *
     * @param caller The caller.
     * @param vaultId The vault.
     * @param allowDeleted Whether a deleted vault is read too: its view and log stay readable to its
     *   members (`PROTOCOL.md` §12.3); nothing else of it is left.
     * @return The vault and the caller's membership.
     * @throws CloakException `not_found` when it does not exist, the caller is not a member, or it
     *   was deleted and [allowDeleted] is false.
     */
    fun readAsMember(caller: UserId, vaultId: VaultId, allowDeleted: Boolean = false): Pair<VaultRow, MemberRow> {
        val membership = MemberRepository.find(vaultId, caller) ?: throw CloakException.notFound("vault")
        val vault = VaultRepository.find(vaultId) ?: throw CloakException.notFound("vault")
        if (vault.isDeleted && !allowDeleted) throw CloakException.notFound("vault")
        return vault to membership
    }

    /**
     * Describes a vault to a member.
     *
     * @param vault The vault.
     * @param member The member's row.
     * @return The view the API returns.
     */
    fun toVault(vault: VaultRow, member: MemberRow): Vault {
        val current = member.envelopeKeyVersion == vault.keyVersion
        return Vault(
            id = vault.id,
            role = member.membership.role,
            keyVersion = vault.keyVersion,
            keyEnvelope = member.keyEnvelope.takeIf { current },
            envelopeUserKeyVersion = member.membership.userKeyVersion.takeIf { current && member.keyEnvelope != null },
            logSeq = vault.logSeq,
            logHeadHash = vault.logHeadHash,
            createdByUserId = vault.createdByUserId,
            createdAt = vault.createdAt,
            accepted = member.accepted,
            addedByUserId = member.addedByUserId,
            deleted = vault.isDeleted,
        )
    }
}
