package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.identity.persistence.IdentitiesTable
import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.protocol.Membership
import dev.voir.cloak.server.vault.domain.Acceptance
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import org.jetbrains.exposed.v1.core.JoinType
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.alias
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.core.neq
import org.jetbrains.exposed.v1.core.notExists
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import org.jetbrains.exposed.v1.jdbc.upsert
import kotlin.time.Instant

/**
 * A stored membership.
 *
 * @property vaultId Vault.
 * @property userId Member.
 * @property membership Role and committed keys.
 * @property keyEnvelope The current vault key sealed to the committed keys, or `null`.
 * @property envelopeKeyVersion Vault key version [keyEnvelope] holds, or `null`.
 * @property addedAt Instant the member was added.
 * @property accepted Whether the server lists the vault as accepted by the member (`PROTOCOL.md` §12.4).
 * @property addedByUserId Who added the member, per the log; `null` for the vault's creator.
 * @property acceptance The member's own signed `vaultAcceptance` (§9), the latest they sent; `null`
 *   when they accepted only the person who added them, or nothing.
 */
internal data class MemberRow(
    /** Vault. */
    val vaultId: VaultId,
    /** Member. */
    val userId: UserId,
    /** Role and committed keys. */
    val membership: Membership,
    /** The member's envelope. */
    val keyEnvelope: ByteString?,
    /** Vault key version of the envelope. */
    val envelopeKeyVersion: Int?,
    /** Instant the member was added. */
    val addedAt: Instant,
    /** Whether the member accepted the vault. */
    val accepted: Boolean = true,
    /** Who added the member. */
    val addedByUserId: UserId? = null,
    /** The member's own signed acceptance. */
    val acceptance: Acceptance? = null,
)

/** Reads and writes `cloak.vault_members`. Every function runs inside the caller's transaction. */
internal object MemberRepository {
    /**
     * Loads one membership.
     *
     * @param vaultId Vault.
     * @param userId User.
     * @return The membership, or `null` when the user is not a member.
     */
    fun find(vaultId: VaultId, userId: UserId): MemberRow? =
        VaultMembersTable.selectAll()
            .where { (VaultMembersTable.vaultId eq vaultId.value) and (VaultMembersTable.userId eq userId.value) }
            .singleOrNull()
            ?.let(::toMember)

    /**
     * Loads every member of a vault.
     *
     * @param vaultId Vault.
     * @return Members by user.
     */
    fun all(vaultId: VaultId): Map<UserId, MemberRow> =
        VaultMembersTable.selectAll()
            .where { VaultMembersTable.vaultId eq vaultId.value }
            .map(::toMember)
            .associateBy(MemberRow::userId)

    /**
     * Returns the vaults a user is a member of.
     *
     * @param userId User.
     * @return The vaults.
     */
    fun vaultsOf(userId: UserId): List<VaultId> =
        VaultMembersTable.select(VaultMembersTable.vaultId)
            .where { VaultMembersTable.userId eq userId.value }
            .map { VaultId(it[VaultMembersTable.vaultId]) }

    /**
     * Returns the vaults of a user in which every other member is a deleted identity, or which have
     * no other member: the vaults nobody could act on once the user's identity is deleted too
     * (`PROTOCOL.md` §5.7). Lock the vaults first, so no membership or deletion of their members
     * changes before the transaction ends: every deletion of a member locks the vault too.
     *
     * @param userId Member.
     * @return Vault ids, deleted vaults included.
     */
    fun vaultsWithoutOtherLiveMembers(userId: UserId): List<VaultId> {
        val others = VaultMembersTable.alias("others")
        val otherLive = others
            .join(IdentitiesTable, JoinType.INNER, others[VaultMembersTable.userId], IdentitiesTable.userId)
            .select(others[VaultMembersTable.userId])
            .where {
                (others[VaultMembersTable.vaultId] eq VaultMembersTable.vaultId) and
                    (others[VaultMembersTable.userId] neq userId.value) and IdentitiesTable.deletedAt.isNull()
            }
        return VaultMembersTable.select(VaultMembersTable.vaultId)
            .where { (VaultMembersTable.userId eq userId.value) and notExists(otherLive) }
            .orderBy(VaultMembersTable.vaultId)
            .map { VaultId(it[VaultMembersTable.vaultId]) }
    }

    /**
     * Clears every envelope sealed to a user, in every vault they are a member of.
     *
     * @param userId User.
     */
    fun clearEnvelopes(userId: UserId) {
        VaultMembersTable.update(where = { VaultMembersTable.userId eq userId.value }) {
            it[keyEnvelope] = null
            it[envelopeKeyVersion] = null
        }
    }

    /**
     * Returns a user's roles in several vaults.
     *
     * @param userId User.
     * @param vaultIds Vaults.
     * @return Role by vault; vaults the user is not a member of are absent.
     */
    fun roles(userId: UserId, vaultIds: Collection<VaultId>): Map<VaultId, Role> {
        if (vaultIds.isEmpty()) return emptyMap()
        return VaultMembersTable.select(VaultMembersTable.vaultId, VaultMembersTable.role)
            .where { (VaultMembersTable.userId eq userId.value) and (VaultMembersTable.vaultId inList vaultIds.map(VaultId::value)) }
            .associate { VaultId(it[VaultMembersTable.vaultId]) to Role.fromCode(it[VaultMembersTable.role]) }
    }

    /**
     * Loads a user's memberships in several vaults, in one query.
     *
     * @param userId User.
     * @param vaultIds Vaults.
     * @return Memberships by vault; vaults the user is not a member of are absent.
     */
    fun memberships(userId: UserId, vaultIds: Collection<VaultId>): Map<VaultId, MemberRow> {
        if (vaultIds.isEmpty()) return emptyMap()
        return VaultMembersTable.selectAll()
            .where { (VaultMembersTable.userId eq userId.value) and (VaultMembersTable.vaultId inList vaultIds.map(VaultId::value)) }
            .map(::toMember)
            .associateBy(MemberRow::vaultId)
    }

    /**
     * Stores a new member.
     *
     * @param row The membership.
     */
    fun insert(row: MemberRow) {
        VaultMembersTable.insert {
            it[vaultId] = row.vaultId.value
            it[userId] = row.userId.value
            it[role] = row.membership.role.code
            it[userKeyVersion] = row.membership.userKeyVersion
            it[keysDigest] = row.membership.keysDigest.toByteArray()
            it[keyEnvelope] = row.keyEnvelope?.toByteArray()
            it[envelopeKeyVersion] = row.envelopeKeyVersion
            it[accepted] = row.accepted
            it[addedByUserId] = row.addedByUserId?.value
            it[acceptanceKeyVersion] = row.acceptance?.keyVersion
            it[acceptanceSignature] = row.acceptance?.signature?.toByteArray()
            it[addedAt] = row.addedAt
        }
    }

    /**
     * Lists the vaults a user accepted and no owner deleted: the memberships that keep them from
     * deleting their identity (`PROTOCOL.md` §5.7, §12.3, §12.4). A vault they never accepted does
     * not, or anyone could hold an account hostage by adding it to a vault.
     *
     * @param userId Member.
     * @return Vault ids.
     */
    fun acceptedLiveVaultsOf(userId: UserId): List<VaultId> =
        (VaultMembersTable innerJoin VaultsTable).select(VaultMembersTable.vaultId)
            .where {
                (VaultMembersTable.userId eq userId.value) and (VaultMembersTable.accepted eq true) and VaultsTable.deletedAt.isNull()
            }
            .map { VaultId(it[VaultMembersTable.vaultId]) }

    /**
     * Counts the vaults a user was added to and has not accepted, deleted ones aside.
     *
     * @param userId Member.
     * @param inviterUserId Only those this person added them to; `null` for all.
     * @return The count.
     */
    fun pendingCount(userId: UserId, inviterUserId: UserId? = null): Long =
        (VaultMembersTable innerJoin VaultsTable).select(VaultMembersTable.vaultId)
            .where {
                val pending = (VaultMembersTable.userId eq userId.value) and (VaultMembersTable.accepted eq false) and
                    VaultsTable.deletedAt.isNull()
                if (inviterUserId == null) pending else pending and (VaultMembersTable.addedByUserId eq inviterUserId.value)
            }
            .count()

    /**
     * Marks a membership accepted with the member's signed acceptance, replacing any earlier one.
     *
     * @param vaultId Vault.
     * @param userId Member.
     * @param acceptance Their verified `vaultAcceptance`.
     */
    fun accept(vaultId: VaultId, userId: UserId, acceptance: Acceptance) {
        VaultMembersTable.update(where = { (VaultMembersTable.vaultId eq vaultId.value) and (VaultMembersTable.userId eq userId.value) }) {
            it[accepted] = true
            it[acceptanceKeyVersion] = acceptance.keyVersion
            it[acceptanceSignature] = acceptance.signature.toByteArray()
        }
    }

    /**
     * Accepts every vault one person added a user to, and remembers to accept their later ones,
     * with the user's signed acceptance of them, which replaces any earlier one. The memberships
     * get no signature of their own.
     *
     * @param userId The user who accepts.
     * @param inviterUserId The person whose vaults they accept.
     * @param acceptance The user's verified `inviterAcceptance`.
     * @param at When; kept from the first acceptance of the person.
     */
    fun acceptFrom(userId: UserId, inviterUserId: UserId, acceptance: Acceptance, at: Instant) {
        VaultMembersTable.update(
            where = { (VaultMembersTable.userId eq userId.value) and (VaultMembersTable.addedByUserId eq inviterUserId.value) },
        ) {
            it[accepted] = true
        }
        AcceptedInvitersTable.upsert(onUpdateExclude = listOf(AcceptedInvitersTable.acceptedAt)) {
            it[AcceptedInvitersTable.userId] = userId.value
            it[AcceptedInvitersTable.inviterUserId] = inviterUserId.value
            it[keyVersion] = acceptance.keyVersion
            it[signature] = acceptance.signature.toByteArray()
            it[acceptedAt] = at
        }
    }

    /**
     * Deletes a user's acceptances of people and people's acceptances of the user, for the
     * deletion of the user's identity: nobody can add them to a vault again or be added by them.
     *
     * @param userId User.
     */
    fun deleteInviterAcceptances(userId: UserId) {
        AcceptedInvitersTable.deleteWhere {
            (AcceptedInvitersTable.userId eq userId.value) or (AcceptedInvitersTable.inviterUserId eq userId.value)
        }
    }

    /**
     * Loads a user's signed acceptances of several people, in one query.
     *
     * @param userId The user who accepted.
     * @param inviterUserIds The people.
     * @return Acceptance by person; people the user has not accepted are absent.
     */
    fun inviterAcceptances(userId: UserId, inviterUserIds: Collection<UserId>): Map<UserId, Acceptance> {
        if (inviterUserIds.isEmpty()) return emptyMap()
        return AcceptedInvitersTable
            .select(AcceptedInvitersTable.inviterUserId, AcceptedInvitersTable.keyVersion, AcceptedInvitersTable.signature)
            .where {
                (AcceptedInvitersTable.userId eq userId.value) and
                    (AcceptedInvitersTable.inviterUserId inList inviterUserIds.map(UserId::value))
            }
            .associate {
                UserId(it[AcceptedInvitersTable.inviterUserId]) to
                    Acceptance(it[AcceptedInvitersTable.keyVersion], it[AcceptedInvitersTable.signature].toByteString())
            }
    }

    /**
     * Whether a user accepts everything from a person.
     *
     * @param userId The user.
     * @param inviterUserId The person.
     * @return Whether they accepted them.
     */
    fun acceptsFrom(userId: UserId, inviterUserId: UserId): Boolean =
        !AcceptedInvitersTable.selectAll()
            .where { (AcceptedInvitersTable.userId eq userId.value) and (AcceptedInvitersTable.inviterUserId eq inviterUserId.value) }
            .empty()

    /**
     * Updates a member's role and committed keys.
     *
     * @param vaultId Vault.
     * @param userId Member.
     * @param membership New role and committed keys.
     */
    fun updateMembership(vaultId: VaultId, userId: UserId, membership: Membership) {
        VaultMembersTable.update(where = { (VaultMembersTable.vaultId eq vaultId.value) and (VaultMembersTable.userId eq userId.value) }) {
            it[role] = membership.role.code
            it[userKeyVersion] = membership.userKeyVersion
            it[keysDigest] = membership.keysDigest.toByteArray()
        }
    }

    /**
     * Stores or clears a member's envelope.
     *
     * @param vaultId Vault.
     * @param userId Member.
     * @param envelope The envelope, or `null` to clear it.
     * @param keyVersion Vault key version it holds, or `null` with it.
     */
    fun setEnvelope(vaultId: VaultId, userId: UserId, envelope: ByteString?, keyVersion: Int?) {
        VaultMembersTable.update(where = { (VaultMembersTable.vaultId eq vaultId.value) and (VaultMembersTable.userId eq userId.value) }) {
            it[keyEnvelope] = envelope?.toByteArray()
            it[envelopeKeyVersion] = keyVersion
        }
    }

    /**
     * Removes a member.
     *
     * @param vaultId Vault.
     * @param userId Member.
     */
    fun delete(vaultId: VaultId, userId: UserId) {
        VaultMembersTable.deleteWhere { (VaultMembersTable.vaultId eq vaultId.value) and (VaultMembersTable.userId eq userId.value) }
    }

    /**
     * Maps a row that holds the member columns.
     *
     * @param row Row of `vault_members`, alone or joined.
     * @return The membership.
     */
    fun toMember(row: ResultRow): MemberRow =
        MemberRow(
            vaultId = VaultId(row[VaultMembersTable.vaultId]),
            userId = UserId(row[VaultMembersTable.userId]),
            membership = Membership(
                role = Role.fromCode(row[VaultMembersTable.role]),
                userKeyVersion = row[VaultMembersTable.userKeyVersion],
                keysDigest = row[VaultMembersTable.keysDigest].toByteString(),
            ),
            keyEnvelope = row[VaultMembersTable.keyEnvelope]?.toByteString(),
            envelopeKeyVersion = row[VaultMembersTable.envelopeKeyVersion],
            addedAt = row[VaultMembersTable.addedAt],
            accepted = row[VaultMembersTable.accepted],
            addedByUserId = row[VaultMembersTable.addedByUserId]?.let(::UserId),
            acceptance = row[VaultMembersTable.acceptanceKeyVersion]?.let { keyVersion ->
                Acceptance(keyVersion, checkNotNull(row[VaultMembersTable.acceptanceSignature]).toByteString())
            },
        )
}
