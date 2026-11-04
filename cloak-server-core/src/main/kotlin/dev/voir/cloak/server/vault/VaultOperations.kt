package dev.voir.cloak.server.vault

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.DatabaseKeyDirectory
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.paging.KeysetCursor
import dev.voir.cloak.server.paging.Page
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.paging.LeafCursor
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.vault.persistence.LeafPosition
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.protocol.LogState
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.protocol.MerkleTree
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.CheckpointLeafPage
import dev.voir.cloak.server.vault.domain.CheckpointProof
import dev.voir.cloak.server.vault.domain.CheckpointProofQuery
import dev.voir.cloak.server.vault.domain.CreateVaultCommand
import dev.voir.cloak.server.vault.domain.LeafProof
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.Vault
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultKey
import dev.voir.cloak.server.vault.domain.VaultLogBatchItem
import dev.voir.cloak.server.vault.domain.VaultLogPage
import dev.voir.cloak.server.vault.domain.VaultLogQuery
import dev.voir.cloak.server.vault.persistence.CheckpointRepository
import dev.voir.cloak.server.vault.persistence.LogRepository
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.MemberRow
import dev.voir.cloak.server.vault.persistence.VaultKeyRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import dev.voir.cloak.server.vault.persistence.VaultRow
import kotlinx.io.bytestring.ByteString

/**
 * Vaults, their keys, logs and checkpoints (`/vaults`).
 *
 * @property context Database and clock.
 */
public class VaultOperations internal constructor(
    private val context: CloakContext,
) {
    /**
     * Lists the caller's vaults, newest first: those they accepted, or with [pending] those they
     * were added to and have not accepted (`PROTOCOL.md` §12.4). Deleted vaults are not listed.
     *
     * @param caller Authenticated user.
     * @param page Page size and cursor.
     * @param pending Whether to list the vaults awaiting the caller's acceptance.
     * @return One page of vaults.
     */
    @JvmOverloads
    public fun list(caller: UserId, page: PageRequest = PageRequest(), pending: Boolean = false): Page<Vault> = context.operation("listVaults") {
        val limit = KeysetCursor.checkLimit(page.limit)
        val after = KeysetCursor.decode(page.cursor, KeysetCursor.Kind.VAULTS)
        asCaller(caller) {
            val rows = VaultRepository.pageForMember(caller, after, limit + 1, pending)
            val items = rows.take(limit)
            val next = items.lastOrNull()?.takeIf { rows.size > limit }?.let { (vault, _) ->
                KeysetCursor(KeysetCursor.Kind.VAULTS, vault.createdAt, vault.id.value).encode()
            }
            Page(items.map { (vault, member) -> VaultAccess.toVault(vault, member) }, next)
        }
    }

    /**
     * Creates a vault with the caller as owner, key version 1 sealed to the caller, and its
     * signed `vault_created` entry.
     *
     * @param caller Authenticated user.
     * @param command Vault id, envelope and entry.
     * @return The new vault.
     * @throws CloakException `identity_required`, `already_exists` for a taken id, and the errors of
     *   [LogAppender.verify].
     */
    public fun create(caller: UserId, command: CreateVaultCommand): Vault = context.operation("createVault") {
        BlobRules.envelope(command.keyEnvelope, "/keyEnvelope")
        Validation.require(command.log.kind == LogEntryKind.VAULT_CREATED, "/log/kind", "log_mismatch", "Must be vault_created.")
        asCaller(caller) {
            val keys = DatabaseKeyDirectory()
            keys.currentVersion(caller) ?: throw CloakException.identityRequired()
            val now = context.clock.now()
            val appender = LogAppender(keys, now, this)
            val request = appender.verify(LogState.empty(command.id), caller, listOf(command.log), emptyList(), "/log")
            val owner = checkNotNull(request.after.members[caller])
            val vault = VaultRow(command.id, 1, 1, checkNotNull(request.after.headHash), 0, 0, 0, null, caller, now)
            if (!VaultRepository.insert(vault)) throw CloakException(CloakErrorCode.ALREADY_EXISTS, "A vault with this id exists.")
            VaultKeyRepository.insert(command.id, 1, checkNotNull(command.log.keyCommitment), null, now)
            val member = MemberRow(command.id, caller, owner, command.keyEnvelope, 1, now)
            MemberRepository.insert(member)
            appender.store(request)
            VaultAccess.toVault(vault, member)
        }
    }

    /**
     * Returns a vault as the caller sees it.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @return The vault.
     * @throws CloakException `not_found` unless the caller is a member.
     */
    public fun get(caller: UserId, vaultId: VaultId): Vault = context.operation("getVault") {
        asCaller(caller) {
            val (vault, member) = VaultAccess.readAsMember(caller, vaultId, allowDeleted = true)
            VaultAccess.toVault(vault, member)
        }
    }

    /**
     * Deletes a vault with an owner's signed `vault_deleted` (`PROTOCOL.md` §12.3): the entry is
     * appended, then the vault's keys, envelopes, sections and checkpoint leaves are removed. The
     * log and member list stay, so members verify who deleted it; nothing follows the entry.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param log The signed `vault_deleted`.
     * @throws CloakException `not_found` unless the caller is a member of a vault not deleted yet,
     *   `role_required` unless an owner, and the errors of [LogAppender.verify].
     */
    public fun delete(caller: UserId, vaultId: VaultId, log: LogEntryInput) {
        Validation.require(log.kind == LogEntryKind.VAULT_DELETED, "/log/kind", "log_mismatch", "Must be vault_deleted.")
        context.operation("deleteVault") {
            asCaller(caller, CloakContext.Budget.CHECKPOINT) {
                val view = VaultAccess.lockForMember(caller, vaultId)
                view.requireRole(Role.OWNER, "delete the vault")
                val appender = LogAppender(DatabaseKeyDirectory(), context.clock.now(), this)
                val request = appender.verify(LogAppender.stateOf(view.vault, view.members), caller, listOf(log), emptyList(), "/log")
                appender.store(request)
            }
        }
    }

    /**
     * Appends one signed node entry: `node_created`, `node_shared` or `node_unshared`
     * (`PROTOCOL.md` §7.7). Only a node's owner creates and shares it, since its id derives from
     * them; anyone may take a share back who is an admin of the vault, or the owner.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param log The signed entry.
     * @return The vault after it.
     * @throws CloakException `validation_failed` for another kind, `not_found` unless the caller is a
     *   member of a vault not deleted, and the errors of [LogAppender.verify].
     */
    public fun appendNodeEntry(caller: UserId, vaultId: VaultId, log: LogEntryInput): Vault = context.operation("appendNodeEntry") {
        Validation.require(log.kind in NODE_KINDS, "/log/kind", "log_mismatch", "Must be node_created, node_shared or node_unshared.")
        asCaller(caller) {
            val view = VaultAccess.lockForMember(caller, vaultId)
            val appender = LogAppender(DatabaseKeyDirectory(), context.clock.now(), this)
            val request = appender.verify(LogAppender.stateOf(view.vault, view.members), caller, listOf(log), emptyList(), "/log")
            appender.store(request)
            val (vault, member) = VaultAccess.readAsMember(caller, vaultId)
            VaultAccess.toVault(vault, member)
        }
    }

    /**
     * Reads several vaults at once: for each one asked, in order, its view and one page of its log
     * after the asked `seq`, or not found when the caller cannot see it (`PROTOCOL.md` §12.4). Every
     * vault asked is answered, so a client treats a missing answer as a failed read.
     *
     * @param caller Authenticated user.
     * @param queries 1 to 100 distinct vaults.
     * @return One answer per query, in query order.
     * @throws CloakException `validation_failed` for an empty, oversized or repeating list.
     */
    public fun getMany(caller: UserId, queries: List<VaultLogQuery>): List<VaultLogBatchItem> = context.operation("batchGetVaults") {
        Validation.size(queries, 1..Limits.MAX_BATCH_SIZE, "/items")
        Validation.unique(queries, "/items") { it.vaultId }
        queries.forEachIndexed { index, query ->
            Validation.require((query.afterSeq ?: 1) >= 1, "/items/$index/afterSeq", "minimum", "Must be at least 1.")
        }
        asCaller(caller) {
            val members = MemberRepository.memberships(caller, queries.map { it.vaultId })
            queries.map { query ->
                // A deleted vault's view and log stay readable to its members (§12.3).
                val member = members[query.vaultId]
                val vault = member?.let { VaultRepository.find(query.vaultId) }
                if (member == null || vault == null) {
                    VaultLogBatchItem(query.vaultId, null, null)
                } else {
                    VaultLogBatchItem(
                        query.vaultId,
                        VaultAccess.toVault(vault, member),
                        VaultLogPage(LogRepository.page(query.vaultId, query.afterSeq ?: 0, PageRequest.DEFAULT_LIMIT), vault.logSeq),
                    )
                }
            }
        }
    }

    /**
     * Reads a vault's log, oldest first.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param afterSeq Only entries after this one; `null` for all.
     * @param limit Page size.
     * @return One page of entries and the head `seq`.
     */
    public fun log(caller: UserId, vaultId: VaultId, afterSeq: Long? = null, limit: Int = PageRequest.DEFAULT_LIMIT): VaultLogPage = context.operation("listVaultLog") {
        KeysetCursor.checkLimit(limit)
        Validation.require((afterSeq ?: 1) >= 1, "#/query/afterSeq", "minimum", "Must be at least 1.")
        asCaller(caller) {
            val (vault, _) = VaultAccess.readAsMember(caller, vaultId, allowDeleted = true)
            VaultLogPage(LogRepository.page(vaultId, afterSeq ?: 0, limit), vault.logSeq)
        }
    }

    /**
     * Lists a vault's key versions, oldest first.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param afterVersion Only versions after this one; `null` for all.
     * @param limit Page size.
     * @return Key versions.
     */
    public fun keys(caller: UserId, vaultId: VaultId, afterVersion: Int? = null, limit: Int = PageRequest.DEFAULT_LIMIT): List<VaultKey> = context.operation("listVaultKeys") {
        KeysetCursor.checkLimit(limit)
        Validation.require((afterVersion ?: 1) >= 1, "#/query/afterVersion", "minimum", "Must be at least 1.")
        asCaller(caller) {
            VaultAccess.readAsMember(caller, vaultId)
            VaultKeyRepository.page(vaultId, afterVersion ?: 0, limit)
        }
    }

    /**
     * Proves what checkpoints of a vault hold for some sections: each section's leaf with its
     * audit path, or the neighbouring leaves that show it is absent (`PROTOCOL.md` §7.5). Each
     * checkpoint named is loaded once and its tree built once, so a proof costs O(log n).
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param queries Up to [Limits.MAX_BATCH_SIZE] distinct sections and checkpoints.
     * @return One proof per query, in query order.
     * @throws CloakException `validation_failed` for an empty, oversized or repeating list; `not_found`
     *   unless the caller is a member and every named entry carries a checkpoint.
     */
    public fun checkpointProofs(caller: UserId, vaultId: VaultId, queries: List<CheckpointProofQuery>): List<CheckpointProof> = context.operation("batchGetCheckpointProofs") {
        Validation.size(queries, 1..Limits.MAX_BATCH_SIZE, "/items")
        Validation.unique(queries, "/items") { it }
        queries.forEachIndexed { index, query ->
            Validation.require(query.checkpointSeq >= 1, "/items/$index/checkpointSeq", "minimum", "Must be at least 1.")
        }
        asCaller(caller, CloakContext.Budget.CHECKPOINT) {
            VaultAccess.readAsMember(caller, vaultId)
            val seqs = queries.map { it.checkpointSeq }.toSet()
            val stored = LogRepository.checkpoints(vaultId, seqs)
            if (stored.keys != seqs) throw CloakException.notFound("checkpoint")
            val leaves = CheckpointRepository.leaves(vaultId, seqs)
            val proofs = seqs.associateWith { seq -> CheckpointProver(seq, leaves[seq].orEmpty()) }
            queries.map { query -> checkNotNull(proofs[query.checkpointSeq]).prove(query.nodeId, query.sectionName) }
        }
    }

    /**
     * Lists one page of a checkpoint's leaves in checkpoint order. A client that reads them all
     * recomputes the root itself and needs no proofs (`PROTOCOL.md` §7.5).
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param seq Log entry carrying the checkpoint.
     * @param cursor `nextCursor` of the previous page, or `null` for the first page.
     * @param limit Page size, up to [PageRequest.MAX_INDEX_LIMIT].
     * @return The page with the checkpoint's size and the cursor of the next page, if any.
     * @throws CloakException `validation_failed` for bad paging or a cursor of another checkpoint;
     *   `not_found` unless the caller is a member and the entry carries a checkpoint.
     */
    public fun checkpointLeaves(
        caller: UserId,
        vaultId: VaultId,
        seq: Long,
        cursor: String? = null,
        limit: Int = PageRequest.MAX_INDEX_LIMIT,
    ): CheckpointLeafPage = context.operation("listCheckpointLeaves") {
        KeysetCursor.checkLimit(limit, PageRequest.MAX_INDEX_LIMIT)
        Validation.require(seq >= 1, "#/path/seq", "minimum", "Must be at least 1.")
        val after = LeafCursor.decode(cursor, seq)
        asCaller(caller, CloakContext.Budget.CHECKPOINT) {
            VaultAccess.readAsMember(caller, vaultId)
            val checkpoint = LogRepository.checkpoints(vaultId, listOf(seq))[seq] ?: throw CloakException.notFound("checkpoint")
            val rows = CheckpointRepository.page(vaultId, seq, after, limit + 1)
            val leaves = rows.take(limit)
            val next = leaves.lastOrNull()?.takeIf { rows.size > limit }?.let { LeafCursor.encode(seq, LeafPosition(it.nodeId, it.sectionName)) }
            CheckpointLeafPage(seq, checkpoint.size, leaves, next)
        }
    }

    /** Constants of vault operations. */
    private companion object {
        /** The kinds [appendNodeEntry] takes. */
        val NODE_KINDS = setOf(LogEntryKind.NODE_CREATED, LogEntryKind.NODE_SHARED, LogEntryKind.NODE_UNSHARED)
    }

    /**
     * Proofs over one checkpoint's leaves, whose tree is built once.
     *
     * @property seq Log entry carrying the checkpoint.
     * @property leaves Leaves in checkpoint order.
     */
    private class CheckpointProver(
        private val seq: Long,
        private val leaves: List<CheckpointLeaf>,
    ) {
        /** The checkpoint's tree. */
        private val tree = MerkleTree(leaves.map(Merkle::leafHash))

        /**
         * Proves what the checkpoint holds for one section.
         *
         * @param nodeId Node of the section.
         * @param sectionName Section name.
         * @return The section's leaf, or the leaves around where it would be.
         */
        fun prove(nodeId: NodeId, sectionName: SectionName): CheckpointProof {
            val probe = CheckpointLeaf(nodeId, sectionName, 1, ByteString(ByteArray(BlobRules.KEY_BYTES)))
            val position = leaves.binarySearch(probe, Merkle.sectionOrder)
            val size = leaves.size.toLong()
            return if (position >= 0) {
                CheckpointProof(seq, size, leafProof(position), null, null)
            } else {
                val insertion = -position - 1
                CheckpointProof(seq, size, null, leafProof(insertion - 1), leafProof(insertion))
            }
        }

        /** The leaf at [index] with its audit path, or `null` outside the tree. */
        private fun leafProof(index: Int): LeafProof? =
            leaves.getOrNull(index)?.let { LeafProof(index.toLong(), it, tree.auditPath(index)) }
    }
}
