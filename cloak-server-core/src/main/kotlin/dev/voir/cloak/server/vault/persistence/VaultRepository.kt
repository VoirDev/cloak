package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.paging.KeysetCursor
import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.section.persistence.SectionRemovalsTable
import dev.voir.cloak.server.section.persistence.SectionsTable
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.core.vendors.ForUpdateOption
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insertIgnore
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import kotlin.time.Instant

/**
 * A stored vault.
 *
 * @property id The vault.
 * @property keyVersion Current vault key version.
 * @property logSeq `seq` of the last log entry.
 * @property logHeadHash `entryHash` of the last log entry.
 * @property changeSeq Change number of the last section change, a write or a removal.
 * @property liveSections Number of sections whose latest write is not a deletion.
 * @property storedSections Number of stored sections, deletions included.
 * @property pause The write pause holding the vault, if one was set; it may have run out.
 * @property createdByUserId Creator.
 * @property createdAt Creation instant.
 * @property deletedAt When an owner's `vault_deleted` ended it (`PROTOCOL.md` §12.3); `null` while it lives.
 */
internal data class VaultRow(
    /** The vault. */
    val id: VaultId,
    /** Current vault key version. */
    val keyVersion: Int,
    /** `seq` of the last log entry. */
    val logSeq: Long,
    /** `entryHash` of the last log entry. */
    val logHeadHash: ByteString,
    /** Change number of the last section change. */
    val changeSeq: Long,
    /** Number of live sections. */
    val liveSections: Int,
    /** Number of stored sections, deletions included. */
    val storedSections: Int,
    /** The write pause, if one was set. */
    val pause: WritePauseRow?,
    /** Creator. */
    val createdByUserId: UserId,
    /** Creation instant. */
    val createdAt: Instant,
    /** When an owner deleted it. */
    val deletedAt: Instant? = null,
) {
    /** Whether an owner deleted the vault: only its log and member list remain. */
    val isDeleted: Boolean get() = deletedAt != null
}

/**
 * A vault's write pause (`PROTOCOL.md` §7.5).
 *
 * @property userId Who holds it.
 * @property byAdmin Whether they paused as an admin, whose pause no one else replaces.
 * @property until When it ends.
 */
internal data class WritePauseRow(
    /** Who holds it. */
    val userId: UserId,
    /** Whether they paused as an admin. */
    val byAdmin: Boolean,
    /** When it ends. */
    val until: Instant,
) {
    /**
     * Whether the pause still holds.
     *
     * @param now The present.
     * @return Whether it ends after [now].
     */
    fun holdsAt(now: Instant): Boolean = until > now
}

/** Reads, locks and writes `cloak.vaults`. Every function runs inside the caller's transaction. */
internal object VaultRepository {
    /**
     * Loads a vault without locking it.
     *
     * @param id The vault.
     * @return The vault, or `null`.
     */
    fun find(id: VaultId): VaultRow? =
        VaultsTable.selectAll().where { VaultsTable.id eq id.value }.singleOrNull()?.toRow()

    /**
     * Locks vaults for the rest of the transaction, in id order so two requests that lock the same
     * vaults never deadlock, and loads them.
     *
     * @param ids Vaults to lock.
     * @return The vaults that exist, by id.
     */
    fun lock(ids: Collection<VaultId>): Map<VaultId, VaultRow> {
        if (ids.isEmpty()) return emptyMap()
        return VaultsTable.selectAll()
            .where { VaultsTable.id inList ids.map(VaultId::value) }
            .orderBy(VaultsTable.id)
            .forUpdate(ForUpdateOption.ForUpdate)
            .map { it.toRow() }
            .associateBy(VaultRow::id)
    }

    /**
     * Stores a new vault unless its id is taken, which a concurrent create may have done.
     *
     * @param vault The vault, at its first log entry.
     * @return Whether the vault was stored.
     */
    fun insert(vault: VaultRow): Boolean =
        VaultsTable.insertIgnore {
            it[id] = vault.id.value
            it[keyVersion] = vault.keyVersion
            it[logSeq] = vault.logSeq
            it[logHeadHash] = vault.logHeadHash.toByteArray()
            it[changeSeq] = vault.changeSeq
            it[liveSectionCount] = vault.liveSections
            it[storedSectionCount] = vault.storedSections
            it[createdByUserId] = vault.createdByUserId.value
            it[createdAt] = vault.createdAt
        }.insertedCount == 1

    /**
     * Moves a locked vault's log head and key version.
     *
     * @param id The vault.
     * @param seq New head `seq`.
     * @param hash New head `entryHash`.
     * @param keyVersion Key version after the head.
     */
    fun updateHead(id: VaultId, seq: Long, hash: ByteString, keyVersion: Int) {
        VaultsTable.update(where = { VaultsTable.id eq id.value }) {
            it[logSeq] = seq
            it[logHeadHash] = hash.toByteArray()
            it[VaultsTable.keyVersion] = keyVersion
        }
    }

    /**
     * Stores a locked vault's last change number and section counts after section changes.
     *
     * @param vault The vault with its new change number and counts.
     */
    fun updateSections(vault: VaultRow) {
        VaultsTable.update(where = { VaultsTable.id eq vault.id.value }) {
            it[changeSeq] = vault.changeSeq
            it[liveSectionCount] = vault.liveSections
            it[storedSectionCount] = vault.storedSections
        }
    }

    /**
     * Sets or clears a locked vault's write pause.
     *
     * @param id The vault.
     * @param pause The new pause, or `null` to end it.
     */
    fun setPause(id: VaultId, pause: WritePauseRow?) {
        VaultsTable.update(where = { VaultsTable.id eq id.value }) {
            it[pauseUserId] = pause?.userId?.value
            it[pauseByAdmin] = pause?.byAdmin
            it[pauseUntil] = pause?.until
        }
    }

    /**
     * Ends the write pauses [userId] holds among some vaults, in one statement that touches only
     * those rows.
     *
     * @param ids The vaults.
     * @param userId The holder.
     */
    fun endPausesOf(ids: Collection<VaultId>, userId: UserId) {
        VaultsTable.update(where = { (VaultsTable.id inList ids.map(VaultId::value)) and (VaultsTable.pauseUserId eq userId.value) }) {
            it[pauseUserId] = null
            it[pauseByAdmin] = null
            it[pauseUntil] = null
        }
    }

    /**
     * Ends a locked vault's write pause if [userId] holds it.
     *
     * @param id The vault.
     * @param userId Its holder.
     */
    fun endPauseOf(id: VaultId, userId: UserId) {
        VaultsTable.update(where = { (VaultsTable.id eq id.value) and (VaultsTable.pauseUserId eq userId.value) }) {
            it[pauseUserId] = null
            it[pauseByAdmin] = null
            it[pauseUntil] = null
        }
    }

    /**
     * Deletes a vault; its keys, members, log and sections go with it. Only the host does this, as
     * when it erases a user; members delete a vault with [markDeleted].
     *
     * @param id The vault.
     */
    fun delete(id: VaultId) {
        VaultsTable.deleteWhere { VaultsTable.id eq id.value }
    }

    /**
     * Ends a locked vault after its owner's `vault_deleted` (`PROTOCOL.md` §12.3): removes its
     * sections, removals, checkpoint leaves, nodes, shares, pauses, envelopes and keys, and keeps its
     * log and member list so members verify who deleted it.
     *
     * @param id The vault.
     * @param at When it was deleted.
     */
    fun markDeleted(id: VaultId, at: Instant) {
        val vaultId = id.value
        SectionsTable.deleteWhere { SectionsTable.vaultId eq vaultId }
        SectionRemovalsTable.deleteWhere { SectionRemovalsTable.vaultId eq vaultId }
        CheckpointLeavesTable.deleteWhere { CheckpointLeavesTable.vaultId eq vaultId }
        NodesTable.deleteWhere { NodesTable.vaultId eq vaultId }
        NodeSharesTable.deleteWhere { NodeSharesTable.vaultId eq vaultId }
        WritePauseRequestsTable.deleteWhere { WritePauseRequestsTable.vaultId eq vaultId }
        VaultMembersTable.update(where = { VaultMembersTable.vaultId eq vaultId }) {
            it[keyEnvelope] = null
            it[envelopeKeyVersion] = null
        }
        VaultKeysTable.deleteWhere { VaultKeysTable.vaultId eq vaultId }
        VaultsTable.update(where = { VaultsTable.id eq vaultId }) {
            it[liveSectionCount] = 0
            it[storedSectionCount] = 0
            it[pauseUserId] = null
            it[pauseByAdmin] = null
            it[pauseUntil] = null
            it[deletedAt] = at
        }
    }

    /**
     * Lists a user's vaults with their memberships, newest first, one page at a time.
     *
     * @param userId Member.
     * @param after Position after the previous page, or `null`.
     * @param limit Page size; one more is read to know whether a next page exists.
     * @param pending Whether to list the vaults the user has not accepted instead of those they did;
     *   deleted vaults are never listed.
     * @return Vaults and memberships.
     */
    fun pageForMember(userId: UserId, after: KeysetCursor?, limit: Int, pending: Boolean = false): List<Pair<VaultRow, MemberRow>> =
        (VaultsTable innerJoin VaultMembersTable)
            .selectAll()
            .where {
                val mine = (VaultMembersTable.userId eq userId.value) and
                    (VaultMembersTable.accepted eq !pending) and VaultsTable.deletedAt.isNull()
                if (after == null) {
                    mine
                } else {
                    mine and (
                        (VaultsTable.createdAt less after.createdAt) or
                            ((VaultsTable.createdAt eq after.createdAt) and (VaultsTable.id greater after.id))
                        )
                }
            }
            .orderBy(VaultsTable.createdAt to SortOrder.DESC, VaultsTable.id to SortOrder.ASC)
            .limit(limit)
            .map { it.toRow() to MemberRepository.toMember(it) }

    /** Maps a row. */
    private fun ResultRow.toRow(): VaultRow =
        VaultRow(
            id = VaultId(this[VaultsTable.id]),
            keyVersion = this[VaultsTable.keyVersion],
            logSeq = this[VaultsTable.logSeq],
            logHeadHash = this[VaultsTable.logHeadHash].toByteString(),
            changeSeq = this[VaultsTable.changeSeq],
            liveSections = this[VaultsTable.liveSectionCount],
            storedSections = this[VaultsTable.storedSectionCount],
            pause = this[VaultsTable.pauseUserId]?.let { holder ->
                WritePauseRow(UserId(holder), checkNotNull(this[VaultsTable.pauseByAdmin]), checkNotNull(this[VaultsTable.pauseUntil]))
            },
            createdByUserId = UserId(this[VaultsTable.createdByUserId]),
            createdAt = this[VaultsTable.createdAt],
            deletedAt = this[VaultsTable.deletedAt],
        )
}
