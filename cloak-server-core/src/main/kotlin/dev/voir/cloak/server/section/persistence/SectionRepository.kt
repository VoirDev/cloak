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
import org.jetbrains.exposed.v1.core.JoinType
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.upsert

/** Reads and writes `cloak.sections`. Every function runs inside the caller's transaction. */
internal object SectionRepository {
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
     * Lists a vault's sections by the change number of their latest write.
     *
     * @param vaultId Vault.
     * @param afterChange Writes after this change number; 0 for all.
     * @param limit Most writes to return.
     * @return Latest writes.
     */
    fun pageByChange(vaultId: VaultId, afterChange: Long, limit: Int): List<SectionWrite> =
        SectionsTable.selectAll()
            .where { (SectionsTable.vaultId eq vaultId.value) and (SectionsTable.changeSeq greater afterChange) }
            .orderBy(SectionsTable.changeSeq to SortOrder.ASC)
            .limit(limit)
            .map { it.toWrite() }

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
            .map { row ->
                SectionHeader(
                    section = row.toRef(),
                    nodeType = NodeType(row[SectionsTable.nodeType]),
                    homeVaultId = VaultId(row[SectionsTable.homeVaultId]),
                    ownerUserId = UserId(row[SectionsTable.ownerUserId]),
                    nodeKey = row[SectionsTable.nodeKey],
                    vaultKeyVersion = row[SectionsTable.vaultKeyVersion],
                    dataVersion = row[SectionsTable.dataVersion],
                    deleted = row[SectionsTable.deleted],
                    logSeq = row[SectionsTable.logSeq],
                    logHeadHash = row[SectionsTable.logHeadHash].toByteString(),
                    previousWriteHash = row[SectionsTable.previousWriteHash]?.toByteString(),
                    writerUserId = UserId(row[SectionsTable.writerUserId]),
                    writerKeyVersion = row[SectionsTable.writerKeyVersion],
                    ciphertextHash = row[SectionsTable.ciphertextHash]?.toByteString(),
                    signature = row[SectionsTable.signature].toByteString(),
                    writeHash = row[SectionsTable.writeHash].toByteString(),
                    changeSeq = row[SectionsTable.changeSeq],
                    writtenAt = row[SectionsTable.writtenAt],
                )
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
     * Loads the sections of nodes in vaults a user belongs to, in one query.
     *
     * @param nodeIds Nodes.
     * @param userId Reader.
     * @return Latest writes by node.
     */
    fun readableByNode(nodeIds: Collection<NodeId>, userId: UserId): Map<NodeId, List<SectionWrite>> {
        if (nodeIds.isEmpty()) return emptyMap()
        return SectionsTable
            .join(
                VaultMembersTable,
                JoinType.INNER,
                additionalConstraint = {
                    (VaultMembersTable.vaultId eq SectionsTable.vaultId) and (VaultMembersTable.userId eq userId.value)
                },
            )
            .select(SectionsTable.columns)
            .where { SectionsTable.nodeId inList nodeIds.map(NodeId::value) }
            .orderBy(SectionsTable.vaultId to SortOrder.ASC, SectionsTable.sectionName to SortOrder.ASC)
            .map { it.toWrite() }
            .groupBy { it.section.nodeId }
    }

    /** Maps a row's section. */
    private fun ResultRow.toRef(): SectionRef =
        SectionRef(
            vaultId = VaultId(this[SectionsTable.vaultId]),
            nodeId = NodeId(this[SectionsTable.nodeId]),
            sectionName = SectionName(this[SectionsTable.sectionName]),
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
