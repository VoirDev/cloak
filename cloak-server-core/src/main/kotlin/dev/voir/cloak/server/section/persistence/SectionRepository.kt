package dev.voir.cloak.server.section.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionHeader
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.section.domain.SectionRemoval
import dev.voir.cloak.server.section.domain.SectionWrite
import dev.voir.cloak.server.section.domain.SectionWriteInput
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.VaultMembersTable
import dev.voir.cloak.server.vault.persistence.VaultsTable
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.protocol.BlobRules
import org.jetbrains.exposed.v1.core.Coalesce
import org.jetbrains.exposed.v1.core.ColumnSet
import org.jetbrains.exposed.v1.core.CustomFunction
import org.jetbrains.exposed.v1.core.Expression
import org.jetbrains.exposed.v1.core.JoinType
import org.jetbrains.exposed.v1.core.LongColumnType
import org.jetbrains.exposed.v1.core.Op
import org.jetbrains.exposed.v1.core.Sum
import org.jetbrains.exposed.v1.core.WindowFrameBound
import org.jetbrains.exposed.v1.core.alias
import org.jetbrains.exposed.v1.core.lessEq
import org.jetbrains.exposed.v1.core.longLiteral
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.core.rowNumber
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.compoundOr
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.upsert

/**
 * Latest writes a read returned with their ciphertext, within one page's bounds.
 *
 * @property writes Whole sections in the read's order; at least one whenever [next] is set.
 * @property next The first section the read matched but left out, or `null` when it returned all.
 */
internal data class BudgetedWrites(
    /** Whole sections in the read's order. */
    val writes: List<SectionWrite>,
    /** The first section left out, or `null`. */
    val next: SectionRef?,
)

/** Reads and writes `cloak.sections`. Every function runs inside the caller's transaction. */
internal object SectionRepository {
    /** Ciphertext bytes of a row, 0 for a deletion; PostgreSQL reads a stored value's size without the value. */
    private val CIPHERTEXT_BYTES: Expression<Long> =
        Coalesce(CustomFunction<Long?>("octet_length", LongColumnType(), SectionsTable.ciphertext), longLiteral(0))

    /**
     * Loads a section's latest write.
     *
     * @param ref The section.
     * @return The write, or `null` when the section was never written.
     */
    fun find(ref: SectionRef): SectionWrite? =
        SectionsTable.selectAll()
            .where {
                (SectionsTable.vaultId eq ref.vaultId.value) and
                    (SectionsTable.nodeId eq ref.nodeId.value) and
                    (SectionsTable.sectionName eq ref.sectionName.value)
            }
            .singleOrNull()
            ?.toWrite()

    /**
     * Stores a section's new latest write, replacing the previous one.
     *
     * @param write The verified write.
     */
    fun upsert(write: SectionWrite) {
        val input = write.input
        SectionsTable.upsert {
            it[vaultId] = write.section.vaultId.value
            it[nodeId] = write.section.nodeId.value
            it[sectionName] = write.section.sectionName.value
            it[nodeType] = input.nodeType.value
            it[homeVaultId] = input.homeVaultId.value
            it[ownerUserId] = input.ownerUserId.value
            it[nodeKey] = input.nodeKey
            it[vaultKeyVersion] = input.vaultKeyVersion
            it[dataVersion] = input.dataVersion
            it[deleted] = input.deleted
            it[logSeq] = input.logSeq
            it[logHeadHash] = input.logHeadHash.toByteArray()
            it[previousWriteHash] = input.previousWriteHash?.toByteArray()
            it[writerUserId] = write.writerUserId.value
            it[writerKeyVersion] = input.writerKeyVersion
            it[ciphertext] = input.ciphertext?.toByteArray()
            it[ciphertextHash] = write.ciphertextHash?.toByteArray()
            it[signature] = input.signature.toByteArray()
            it[writeHash] = write.writeHash.toByteArray()
            it[changeSeq] = write.changeSeq
            it[writtenAt] = write.writtenAt
        }
    }

    /**
     * Returns the latest write of every live section of a vault as checkpoint leaves, without the
     * ciphertext. A section whose latest write is a deletion is never a leaf (`PROTOCOL.md` §7.5).
     *
     * @param vaultId Vault.
     * @return Leaves in no particular order.
     */
    fun leaves(vaultId: VaultId): List<CheckpointLeaf> =
        SectionsTable.select(SectionsTable.nodeId, SectionsTable.sectionName, SectionsTable.dataVersion, SectionsTable.writeHash)
            .where { (SectionsTable.vaultId eq vaultId.value) and (SectionsTable.deleted eq false) }
            .map {
                CheckpointLeaf(
                    nodeId = NodeId(it[SectionsTable.nodeId]),
                    sectionName = SectionName(it[SectionsTable.sectionName]),
                    dataVersion = it[SectionsTable.dataVersion],
                    writeHash = it[SectionsTable.writeHash].toByteString(),
                )
            }

    /**
     * Lists a vault's sections by the change number of their latest write, held to [limit]
     * sections and one page's budget of ciphertext ([Limits.MAX_PAGE_BYTES]).
     *
     * @param vaultId Vault.
     * @param afterChange Writes after this change number; 0 for all.
     * @param limit Most writes to return.
     * @return Latest writes by change number, and the first one left for the next page.
     */
    fun pageByChange(vaultId: VaultId, afterChange: Long, limit: Int): BudgetedWrites =
        budgeted(
            source = SectionsTable,
            where = (SectionsTable.vaultId eq vaultId.value) and (SectionsTable.changeSeq greater afterChange),
            order = listOf(SectionsTable.changeSeq to SortOrder.ASC),
            limit = limit,
        )

    /**
     * Lists a vault's section headers by the change number of their latest write, without reading
     * the ciphertext.
     *
     * @param vaultId Vault.
     * @param afterChange Writes after this change number; 0 for all.
     * @param limit Most headers to return.
     * @return Latest writes without their ciphertext.
     */
    fun headersByChange(vaultId: VaultId, afterChange: Long, limit: Int): List<SectionHeader> =
        SectionsTable.select(SectionsTable.columns - SectionsTable.ciphertext)
            .where { (SectionsTable.vaultId eq vaultId.value) and (SectionsTable.changeSeq greater afterChange) }
            .orderBy(SectionsTable.changeSeq to SortOrder.ASC)
            .limit(limit)
            .map { it.toHeader() }

    /**
     * Loads the latest write headers of sections in live vaults a user belongs to, in one query,
     * without reading the ciphertext.
     *
     * @param sections Sections.
     * @param userId Reader.
     * @return Headers of the sections found, by section.
     */
    fun readableHeaders(sections: Collection<SectionRef>, userId: UserId): Map<SectionRef, SectionHeader> {
        if (sections.isEmpty()) return emptyMap()
        return SectionsTable
            .join(
                VaultMembersTable,
                JoinType.INNER,
                additionalConstraint = {
                    (VaultMembersTable.vaultId eq SectionsTable.vaultId) and (VaultMembersTable.userId eq userId.value)
                },
            )
            .join(VaultsTable, JoinType.INNER, additionalConstraint = { VaultsTable.id eq SectionsTable.vaultId })
            .select(SectionsTable.columns - SectionsTable.ciphertext)
            .where {
                VaultsTable.deletedAt.isNull() and sections.map { ref ->
                    (SectionsTable.vaultId eq ref.vaultId.value) and
                        (SectionsTable.nodeId eq ref.nodeId.value) and
                        (SectionsTable.sectionName eq ref.sectionName.value)
                }.compoundOr()
            }
            .map { it.toHeader() }
            .associateBy { it.section }
    }

    /**
     * Lists the sections the host removed from a vault, by change number.
     *
     * @param vaultId Vault.
     * @param afterChange Removals after this change number; 0 for all.
     * @param limit Most removals to return.
     * @return Removals.
     */
    fun removalsByChange(vaultId: VaultId, afterChange: Long, limit: Int): List<SectionRemoval> =
        SectionRemovalsTable.selectAll()
            .where { (SectionRemovalsTable.vaultId eq vaultId.value) and (SectionRemovalsTable.changeSeq greater afterChange) }
            .orderBy(SectionRemovalsTable.changeSeq to SortOrder.ASC)
            .limit(limit)
            .map {
                SectionRemoval(
                    NodeId(it[SectionRemovalsTable.nodeId]),
                    SectionName(it[SectionRemovalsTable.sectionName]),
                    it[SectionRemovalsTable.changeSeq],
                )
            }

    /**
     * Loads one page of a node's sections in vaults a user belongs to, by vault and then section
     * name, held to [limit] sections and one page's budget of ciphertext ([Limits.MAX_PAGE_BYTES]).
     *
     * @param nodeId Node.
     * @param userId Reader.
     * @param after The last section of the previous page, or `null` for the first page.
     * @param limit Most sections to return.
     * @return Latest writes in that order, and the first one left for the next page.
     */
    fun readableByNode(nodeId: NodeId, userId: UserId, after: SectionRef?, limit: Int): BudgetedWrites {
        val ofNode = SectionsTable.nodeId eq nodeId.value
        return budgeted(
            source = readableBy(userId),
            where = if (after == null) {
                ofNode
            } else {
                ofNode and ((SectionsTable.vaultId greater after.vaultId.value) or
                    ((SectionsTable.vaultId eq after.vaultId.value) and (SectionsTable.sectionName greater after.sectionName.value)))
            },
            order = listOf(SectionsTable.vaultId to SortOrder.ASC, SectionsTable.sectionName to SortOrder.ASC),
            limit = limit,
        )
    }

    /**
     * Loads one page of the sections of several nodes in vaults a user belongs to, by node, vault
     * and section name, held to [limit] sections and one page's budget of ciphertext
     * ([Limits.MAX_PAGE_BYTES]) together.
     *
     * @param nodeIds Nodes.
     * @param userId Reader.
     * @param limit Most sections to return.
     * @return Latest writes in that order, and the first one left for another read.
     */
    fun readableByNodes(nodeIds: Collection<NodeId>, userId: UserId, limit: Int): BudgetedWrites =
        budgeted(
            source = readableBy(userId),
            where = SectionsTable.nodeId inList nodeIds.map(NodeId::value),
            order = listOf(SectionsTable.nodeId to SortOrder.ASC, SectionsTable.vaultId to SortOrder.ASC, SectionsTable.sectionName to SortOrder.ASC),
            limit = limit,
        )

    /** Sections in the vaults [userId] is a member of. */
    private fun readableBy(userId: UserId): ColumnSet =
        SectionsTable.join(
            VaultMembersTable,
            JoinType.INNER,
            additionalConstraint = {
                (VaultMembersTable.vaultId eq SectionsTable.vaultId) and (VaultMembersTable.userId eq userId.value)
            },
        )

    /**
     * Reads latest writes with their ciphertext in [order], as many whole sections as fit in
     * [limit] and [Limits.MAX_PAGE_BYTES] of ciphertext, in one statement.
     *
     * A subquery numbers the matching sections and sums their ciphertext sizes up to each, without
     * the ciphertext: `octet_length` reads a stored value's size, not the value. Only the sections
     * within both bounds are joined back for their whole rows, so the statement never loads more
     * ciphertext than one page's budget. The first section always fits, since a section is at
     * most [BlobRules.MAX_CIPHERTEXT_BYTES], which the budget holds. The subquery reads one section
     * past [limit], so the result tells whether the read is complete.
     *
     * @param source Table or join the sections come from.
     * @param where Which sections.
     * @param order Their order, ending in a unique key.
     * @param limit Most sections to return.
     * @return The writes that fit, and the first matching section left out.
     */
    private fun budgeted(source: ColumnSet, where: Op<Boolean>, order: List<Pair<Expression<*>, SortOrder>>, limit: Int): BudgetedWrites {
        val sorted = order.toTypedArray()
        val position = rowNumber().over().orderBy(*sorted).alias("position")
        val bytesThrough = Sum(CIPHERTEXT_BYTES, LongColumnType()).over().orderBy(*sorted)
            .rows(WindowFrameBound.unboundedPreceding(), WindowFrameBound.currentRow())
            .alias("bytes_through")
        val planned = source
            .select(SectionsTable.vaultId, SectionsTable.nodeId, SectionsTable.sectionName, position, bytesThrough)
            .where(where)
            .orderBy(*sorted)
            .limit(limit + 1)
            .alias("planned")
        val plannedVault = planned[SectionsTable.vaultId]
        val plannedNode = planned[SectionsTable.nodeId]
        val plannedName = planned[SectionsTable.sectionName]
        val rows = planned
            .join(
                SectionsTable,
                JoinType.LEFT,
                additionalConstraint = {
                    (SectionsTable.vaultId eq plannedVault) and (SectionsTable.nodeId eq plannedNode) and
                        (SectionsTable.sectionName eq plannedName) and (planned[position] lessEq limit.toLong()) and
                        (planned[bytesThrough] lessEq Limits.MAX_PAGE_BYTES.toLong())
                },
            )
            .select(listOf(plannedVault, plannedNode, plannedName) + SectionsTable.columns)
            .orderBy(planned[position] to SortOrder.ASC)
            .toList()
        // Both bounds only grow along the order, so the rows that fit come first.
        val fitting = rows.takeWhile { it.getOrNull(SectionsTable.writeHash) != null }
        val next = rows.getOrNull(fitting.size)?.let {
            SectionRef(VaultId(it[plannedVault]), NodeId(it[plannedNode]), SectionName(it[plannedName]))
        }
        check(next == null || fitting.isNotEmpty()) { "A page holds at least one section" }
        return BudgetedWrites(fitting.map { it.toWrite() }, next)
    }

    /** Maps a row's section. */
    private fun ResultRow.toRef(): SectionRef =
        SectionRef(
            vaultId = VaultId(this[SectionsTable.vaultId]),
            nodeId = NodeId(this[SectionsTable.nodeId]),
            sectionName = SectionName(this[SectionsTable.sectionName]),
        )

    /** Maps a row read without its ciphertext. */
    private fun ResultRow.toHeader(): SectionHeader =
        SectionHeader(
            section = toRef(),
            nodeType = NodeType(this[SectionsTable.nodeType]),
            homeVaultId = VaultId(this[SectionsTable.homeVaultId]),
            ownerUserId = UserId(this[SectionsTable.ownerUserId]),
            nodeKey = this[SectionsTable.nodeKey],
            vaultKeyVersion = this[SectionsTable.vaultKeyVersion],
            dataVersion = this[SectionsTable.dataVersion],
            deleted = this[SectionsTable.deleted],
            logSeq = this[SectionsTable.logSeq],
            logHeadHash = this[SectionsTable.logHeadHash].toByteString(),
            previousWriteHash = this[SectionsTable.previousWriteHash]?.toByteString(),
            writerUserId = UserId(this[SectionsTable.writerUserId]),
            writerKeyVersion = this[SectionsTable.writerKeyVersion],
            ciphertextHash = this[SectionsTable.ciphertextHash]?.toByteString(),
            signature = this[SectionsTable.signature].toByteString(),
            writeHash = this[SectionsTable.writeHash].toByteString(),
            changeSeq = this[SectionsTable.changeSeq],
            writtenAt = this[SectionsTable.writtenAt],
        )

    /** Maps a row. */
    private fun ResultRow.toWrite(): SectionWrite =
        SectionWrite(
            section = toRef(),
            input = SectionWriteInput(
                nodeType = NodeType(this[SectionsTable.nodeType]),
                vaultKeyVersion = this[SectionsTable.vaultKeyVersion],
                dataVersion = this[SectionsTable.dataVersion],
                deleted = this[SectionsTable.deleted],
                logSeq = this[SectionsTable.logSeq],
                logHeadHash = this[SectionsTable.logHeadHash].toByteString(),
                previousWriteHash = this[SectionsTable.previousWriteHash]?.toByteString(),
                writerKeyVersion = this[SectionsTable.writerKeyVersion],
                ciphertext = this[SectionsTable.ciphertext]?.toByteString(),
                signature = this[SectionsTable.signature].toByteString(),
                homeVaultId = VaultId(this[SectionsTable.homeVaultId]),
                ownerUserId = UserId(this[SectionsTable.ownerUserId]),
                nodeKey = this[SectionsTable.nodeKey],
            ),
            writerUserId = UserId(this[SectionsTable.writerUserId]),
            ciphertextHash = this[SectionsTable.ciphertextHash]?.toByteString(),
            writeHash = this[SectionsTable.writeHash].toByteString(),
            changeSeq = this[SectionsTable.changeSeq],
            writtenAt = this[SectionsTable.writtenAt],
        )
}
