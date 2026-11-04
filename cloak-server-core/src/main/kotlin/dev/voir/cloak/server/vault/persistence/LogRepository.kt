package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.vault.domain.LogEntry
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNotNull
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll

/**
 * A checkpoint as the log stores it.
 *
 * @property seq Entry carrying it.
 * @property root The signed root.
 * @property size Number of leaves.
 */
internal data class StoredCheckpoint(
    /** Entry carrying it. */
    val seq: Long,
    /** The signed root. */
    val root: ByteString,
    /** Number of leaves. */
    val size: Int,
)

/** Reads and appends `cloak.vault_log`. Every function runs inside the caller's transaction. */
internal object LogRepository {
    /**
     * Appends verified entries.
     *
     * @param entries Entries in `seq` order.
     * @param checkpointSize Number of leaves of the checkpoint one of the entries carries, if any.
     */
    fun insert(entries: List<LogEntry>, checkpointSize: Int? = null) {
        require((checkpointSize != null) == entries.any { it.input.checkpoint != null }) {
            "A checkpoint is stored with its size."
        }
        VaultLogTable.batchInsert(entries, shouldReturnGeneratedValues = false) { entry ->
            val input = entry.input
            this[VaultLogTable.vaultId] = entry.vaultId.value
            this[VaultLogTable.seq] = input.seq
            this[VaultLogTable.kind] = input.kind.code
            this[VaultLogTable.subjectUserId] = input.subjectUserId?.value
            this[VaultLogTable.role] = input.role?.code
            this[VaultLogTable.keyVersion] = input.keyVersion
            this[VaultLogTable.subjectKeys] = input.subjectKeys?.toByteArray()
            this[VaultLogTable.subjectKeyVersion] = input.subjectKeyVersion
            this[VaultLogTable.keyCommitment] = input.keyCommitment?.toByteArray()
            this[VaultLogTable.checkpoint] = input.checkpoint?.toByteArray()
            this[VaultLogTable.checkpointSize] = if (input.checkpoint == null) null else checkpointSize
            this[VaultLogTable.requestEnd] = input.requestEnd
            this[VaultLogTable.authorUserId] = entry.authorUserId.value
            this[VaultLogTable.authorKeyVersion] = input.authorKeyVersion
            this[VaultLogTable.nodeId] = input.nodeId?.value
            this[VaultLogTable.homeVaultId] = input.homeVaultId?.value
            this[VaultLogTable.nodeKey] = input.nodeKey
            this[VaultLogTable.sections] = input.sections
            this[VaultLogTable.signature] = input.signature.toByteArray()
            this[VaultLogTable.entryHash] = entry.entryHash.toByteArray()
            this[VaultLogTable.createdAt] = entry.createdAt
        }
    }

    /**
     * Lists entries after a position, in `seq` order.
     *
     * @param vaultId Vault.
     * @param afterSeq Entries after this one; 0 for all.
     * @param limit Most entries to return.
     * @return Entries.
     */
    fun page(vaultId: VaultId, afterSeq: Long, limit: Int): List<LogEntry> =
        VaultLogTable.selectAll()
            .where { (VaultLogTable.vaultId eq vaultId.value) and (VaultLogTable.seq greater afterSeq) }
            .orderBy(VaultLogTable.seq to SortOrder.ASC)
            .limit(limit)
            .map { it.toEntry() }

    /**
     * Returns the checkpoints some entries carry.
     *
     * @param vaultId Vault.
     * @param seqs Entries.
     * @return The stored checkpoints by entry; entries that do not exist or carry none are absent.
     */
    fun checkpoints(vaultId: VaultId, seqs: Collection<Long>): Map<Long, StoredCheckpoint> {
        if (seqs.isEmpty()) return emptyMap()
        return VaultLogTable.select(VaultLogTable.seq, VaultLogTable.checkpoint, VaultLogTable.checkpointSize)
            .where {
                (VaultLogTable.vaultId eq vaultId.value) and (VaultLogTable.seq inList seqs) and
                    VaultLogTable.checkpoint.isNotNull()
            }
            .associate {
                it[VaultLogTable.seq] to StoredCheckpoint(
                    seq = it[VaultLogTable.seq],
                    root = checkNotNull(it[VaultLogTable.checkpoint]).toByteString(),
                    size = checkNotNull(it[VaultLogTable.checkpointSize]),
                )
            }
    }

    /** Maps a row. */
    private fun ResultRow.toEntry(): LogEntry =
        LogEntry(
            vaultId = VaultId(this[VaultLogTable.vaultId]),
            input = LogEntryInput(
                seq = this[VaultLogTable.seq],
                kind = LogEntryKind.fromCode(this[VaultLogTable.kind]),
                subjectUserId = this[VaultLogTable.subjectUserId]?.let(::UserId),
                role = this[VaultLogTable.role]?.let(Role::fromCode),
                keyVersion = this[VaultLogTable.keyVersion],
                subjectKeys = this[VaultLogTable.subjectKeys]?.toByteString(),
                subjectKeyVersion = this[VaultLogTable.subjectKeyVersion],
                keyCommitment = this[VaultLogTable.keyCommitment]?.toByteString(),
                checkpoint = this[VaultLogTable.checkpoint]?.toByteString(),
                requestEnd = this[VaultLogTable.requestEnd],
                authorKeyVersion = this[VaultLogTable.authorKeyVersion],
                signature = this[VaultLogTable.signature].toByteString(),
                nodeId = this[VaultLogTable.nodeId]?.let(::NodeId),
                homeVaultId = this[VaultLogTable.homeVaultId]?.let(::VaultId),
                nodeKey = this[VaultLogTable.nodeKey],
                sections = this[VaultLogTable.sections],
            ),
            authorUserId = UserId(this[VaultLogTable.authorUserId]),
            entryHash = this[VaultLogTable.entryHash].toByteString(),
            createdAt = this[VaultLogTable.createdAt],
        )
}
