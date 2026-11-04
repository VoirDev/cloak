package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.VaultId
import org.jetbrains.exposed.v1.core.Op
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.core.lessEq
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update

/**
 * Where a page of a checkpoint's leaves continues: after this section, in checkpoint order.
 *
 * @property nodeId Node of the last section of the previous page.
 * @property sectionName Name of that section.
 */
internal data class LeafPosition(
    /** Node of the last section of the previous page. */
    val nodeId: NodeId,
    /** Name of that section. */
    val sectionName: SectionName,
)

/**
 * Reads and writes `cloak.checkpoint_leaves`, where each row is one section's leaf over a span of
 * checkpoints. Every function runs inside the caller's transaction.
 */
internal object CheckpointRepository {
    /** Most sections one statement closes; keeps the statement's parameter list bounded. */
    private const val CLOSE_CHUNK = 1_000

    /**
     * Stores the leaves of a new checkpoint, the latest of its vault: spans whose leaf the checkpoint
     * no longer holds end at it, and leaves it holds that no open span has start at it. Sections
     * whose leaf did not change keep their span, so this writes only what changed.
     *
     * @param vaultId Vault.
     * @param seq Entry carrying the checkpoint; insert it first, after every earlier checkpoint.
     * @param sortedLeaves The checkpoint's leaves in checkpoint order.
     */
    fun store(vaultId: VaultId, seq: Long, sortedLeaves: List<CheckpointLeaf>) {
        val open = openLeaves(vaultId)
        val wanted = sortedLeaves.associateBy { it.nodeId to it.sectionName }
        val ended = open.filter { (section, leaf) -> wanted[section] != leaf }.keys
        val started = wanted.filter { (section, leaf) -> open[section] != leaf }.values
        ended.chunked(CLOSE_CHUNK).forEach { chunk ->
            CheckpointLeavesTable.update(
                where = {
                    (CheckpointLeavesTable.vaultId eq vaultId.value) and CheckpointLeavesTable.untilSeq.isNull() and
                        ((CheckpointLeavesTable.nodeId to CheckpointLeavesTable.sectionName) inList chunk.map { it.first.value to it.second.value })
                },
            ) { it[untilSeq] = seq }
        }
        CheckpointLeavesTable.batchInsert(started, shouldReturnGeneratedValues = false) { leaf ->
            this[CheckpointLeavesTable.vaultId] = vaultId.value
            this[CheckpointLeavesTable.nodeId] = leaf.nodeId.value
            this[CheckpointLeavesTable.sectionName] = leaf.sectionName.value
            this[CheckpointLeavesTable.dataVersion] = leaf.dataVersion
            this[CheckpointLeavesTable.writeHash] = leaf.writeHash.toByteArray()
            this[CheckpointLeavesTable.fromSeq] = seq
        }
    }

    /**
     * Loads the leaves of some checkpoints in checkpoint order, in one query.
     *
     * @param vaultId Vault.
     * @param seqs Entries carrying the checkpoints.
     * @return Leaves by entry; every entry of [seqs] is present, a checkpoint without leaves empty.
     */
    fun leaves(vaultId: VaultId, seqs: Collection<Long>): Map<Long, List<CheckpointLeaf>> {
        if (seqs.isEmpty()) return emptyMap()
        val result = seqs.associateWith { mutableListOf<CheckpointLeaf>() }
        val first = seqs.min()
        val last = seqs.max()
        CheckpointLeavesTable.selectAll()
            .where {
                (CheckpointLeavesTable.vaultId eq vaultId.value) and (CheckpointLeavesTable.fromSeq lessEq last) and
                    (CheckpointLeavesTable.untilSeq.isNull() or (CheckpointLeavesTable.untilSeq greater first))
            }
            .orderBy(CheckpointLeavesTable.nodeId to SortOrder.ASC, CheckpointLeavesTable.sectionName to SortOrder.ASC)
            .forEach { row ->
                val from = row[CheckpointLeavesTable.fromSeq]
                val until = row[CheckpointLeavesTable.untilSeq] ?: Long.MAX_VALUE
                val leaf = row.toLeaf()
                result.forEach { (seq, leaves) -> if (seq in from until until) leaves += leaf }
            }
        return result
    }

    /**
     * Loads one page of a checkpoint's leaves in checkpoint order.
     *
     * @param vaultId Vault.
     * @param seq Entry carrying the checkpoint.
     * @param after The last section of the previous page, or `null` for the first page.
     * @param limit Most leaves to return.
     * @return The leaves after [after].
     */
    fun page(vaultId: VaultId, seq: Long, after: LeafPosition?, limit: Int): List<CheckpointLeaf> =
        CheckpointLeavesTable.selectAll()
            .where {
                val inCheckpoint = (CheckpointLeavesTable.vaultId eq vaultId.value) and
                    (CheckpointLeavesTable.fromSeq lessEq seq) and
                    (CheckpointLeavesTable.untilSeq.isNull() or (CheckpointLeavesTable.untilSeq greater seq))
                if (after == null) inCheckpoint else inCheckpoint and after.precedes()
            }
            .orderBy(CheckpointLeavesTable.nodeId to SortOrder.ASC, CheckpointLeavesTable.sectionName to SortOrder.ASC)
            .limit(limit)
            .map { it.toLeaf() }

    /** Sections after this position in checkpoint order. */
    private fun LeafPosition.precedes(): Op<Boolean> =
        (CheckpointLeavesTable.nodeId greater nodeId.value) or
            ((CheckpointLeavesTable.nodeId eq nodeId.value) and (CheckpointLeavesTable.sectionName greater sectionName.value))

    /** The leaf of every open span of a vault, by section. */
    private fun openLeaves(vaultId: VaultId): Map<Pair<NodeId, SectionName>, CheckpointLeaf> =
        CheckpointLeavesTable
            .select(CheckpointLeavesTable.nodeId, CheckpointLeavesTable.sectionName, CheckpointLeavesTable.dataVersion, CheckpointLeavesTable.writeHash)
            .where { (CheckpointLeavesTable.vaultId eq vaultId.value) and CheckpointLeavesTable.untilSeq.isNull() }
            .associate { row -> row.toLeaf().let { (it.nodeId to it.sectionName) to it } }

    /** Maps a row. */
    private fun ResultRow.toLeaf(): CheckpointLeaf =
        CheckpointLeaf(
            nodeId = NodeId(this[CheckpointLeavesTable.nodeId]),
            sectionName = SectionName(this[CheckpointLeavesTable.sectionName]),
            dataVersion = this[CheckpointLeavesTable.dataVersion],
            writeHash = this[CheckpointLeavesTable.writeHash].toByteString(),
        )
}
