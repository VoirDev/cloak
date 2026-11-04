package dev.voir.cloak.server.vault

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.DatabaseKeyDirectory
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.protocol.LogFields
import dev.voir.cloak.server.protocol.LogRules
import dev.voir.cloak.server.protocol.LogState
import dev.voir.cloak.server.protocol.LogViolation
import dev.voir.cloak.server.protocol.NodeLedger
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.SignedLogEntry
import dev.voir.cloak.server.protocol.isAbsent
import dev.voir.cloak.server.protocol.sha256
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.persistence.SectionRepository
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.LeftOutWrite
import dev.voir.cloak.server.vault.domain.LogEntry
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.CheckpointRepository
import dev.voir.cloak.server.vault.persistence.LogRepository
import dev.voir.cloak.server.vault.persistence.MemberRow
import dev.voir.cloak.server.vault.persistence.NodeRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import dev.voir.cloak.server.vault.persistence.VaultRow
import kotlin.time.Instant
import kotlin.uuid.Uuid
import org.slf4j.LoggerFactory
import dev.voir.cloak.server.persistence.EventRecorder

/**
 * A request's entries once verified: each entry and the vault's state after it.
 *
 * @property entries The entries, ready to store.
 * @property states The state after each entry; the last is the vault's new state.
 * @property checkpointLeaves Leaves of the request's checkpoint, in checkpoint order, if it carries one.
 */
internal data class VerifiedRequest(
    /** The entries, ready to store. */
    val entries: List<LogEntry>,
    /** The state after each entry. */
    val states: List<LogState>,
    /** Leaves of the request's checkpoint. */
    val checkpointLeaves: List<CheckpointLeaf>?,
) {
    /** The vault's state after the request. */
    val after: LogState get() = states.last()
}

/**
 * Verifies and stores the log entries of one request (`PROTOCOL.md` §7, §13). The caller holds the
 * vault's row lock for the whole transaction, so the state it verifies against cannot move.
 *
 * @property keys Key versions the server holds, read once per transaction.
 * @property now Instant of the request.
 * @property events Where stored entries and checkpoints are recorded, reported after commit.
 */
internal class LogAppender(
    private val keys: DatabaseKeyDirectory,
    private val now: Instant,
    private val events: EventRecorder,
) {
    /**
     * Verifies a request's entries against the vault's state, with its checkpoint if it carries one.
     *
     * @param state State before the request.
     * @param author The caller, who signs every entry.
     * @param inputs The request's entries.
     * @param leftOut Latest writes the request's checkpoint leaves out.
     * @param pointer JSON Pointer of the entries, for errors; list items are `pointer/i`.
     * @param isList Whether the request carries a list of entries rather than one.
     * @return The verified request.
     * @throws CloakException `log_conflict` when the log moved on, `bad_signature`,
     *   `role_required`, `identity_version_conflict`, `log_rejected` for any other rule,
     *   `checkpoint_conflict` when the checkpoint does not match the stored latest writes,
     *   `validation_failed` for malformed fields.
     */
    fun verify(
        state: LogState,
        author: UserId,
        inputs: List<LogEntryInput>,
        leftOut: List<LeftOutWrite>,
        pointer: String,
        isList: Boolean = false,
    ): VerifiedRequest {
        inputs.forEachIndexed { index, input -> checkShape(input, if (isList) "$pointer/$index" else pointer) }
        val first = inputs.first()
        if (first.seq != state.seq + 1) {
            throw CloakException(
                CloakErrorCode.LOG_CONFLICT,
                "The log of the vault is at ${state.seq}; sign entry ${state.seq + 1}.",
                currentVersion = state.seq,
            )
        }
        var previousHash = state.headHash
        val signed = inputs.map { input ->
            val fields = LogFields(
                vaultId = state.vaultId,
                seq = input.seq,
                previousHash = previousHash,
                kind = input.kind,
                subjectUserId = input.subjectUserId,
                role = input.role,
                keyVersion = input.keyVersion,
                subjectKeys = input.subjectKeys,
                subjectKeyVersion = input.subjectKeyVersion,
                keyCommitment = input.keyCommitment,
                checkpoint = input.checkpoint,
                requestEnd = input.requestEnd,
                authorUserId = author,
                authorKeyVersion = input.authorKeyVersion,
                nodeId = input.nodeId,
                homeVaultId = input.homeVaultId,
                nodeKey = input.nodeKey.orEmpty(),
                sections = input.sections.orEmpty(),
            )
            previousHash = sha256(Messages.logEntry(fields))
            SignedLogEntry(fields, input.signature)
        }
        val states = try {
            LogRules.applyRequest(state, signed, keys)
        } catch (violation: LogViolation) {
            throw violation.toException()
        }
        val entries = inputs.zip(states) { input, after ->
            LogEntry(state.vaultId, input, author, checkNotNull(after.headHash), now)
        }
        return VerifiedRequest(entries, states, checkpoint(state.vaultId, inputs, leftOut))
    }

    /**
     * Stores a verified request and moves the vault's head. For a new vault, insert the vault, its
     * first key and its owner first.
     *
     * A checkpoint's leaves are stored as spans and then read back from them: unless the list read
     * back has the signed root and the stored size, the transaction fails, so a checkpoint the
     * server could not prove is never committed. A request with a checkpoint ends its author's
     * write pause of the vault, which existed for it (`PROTOCOL.md` §7.5).
     *
     * @param request The verified request.
     * @throws IllegalStateException when the stored leaves do not give the signed checkpoint, a
     *   server bug that rolls the request back.
     */
    fun store(request: VerifiedRequest) {
        LogRepository.insert(request.entries, request.checkpointLeaves?.size)
        val vaultId = request.after.vaultId
        request.checkpointLeaves?.let { leaves ->
            val entry = request.entries.single { !isAbsent(it.input.checkpoint) }.input
            CheckpointRepository.store(vaultId, entry.seq, leaves)
            val stored = checkNotNull(CheckpointRepository.leaves(vaultId, listOf(entry.seq))[entry.seq])
            if (stored.size != leaves.size || Merkle.root(stored) != entry.checkpoint) {
                logger.error("A stored checkpoint does not read back as signed; the request is rolled back")
                error("The stored checkpoint does not read back as signed")
            }
            events.record { it.checkpointStored(leaves.size) }
            VaultRepository.endPauseOf(vaultId, request.entries.first().authorUserId)
        }
        request.entries.forEach { entry -> events.record { it.logEntryAppended(entry.input.kind.code) } }
        val after = request.after
        VaultRepository.updateHead(vaultId, after.seq, checkNotNull(after.headHash), after.keyVersion)
        NodeRepository.store(vaultId, after.nodes)
        if (after.deleted) VaultRepository.markDeleted(vaultId, now)
    }

    /**
     * Computes the leaves of the request's checkpoint from the stored latest writes and checks the
     * signed root (`PROTOCOL.md` §7.5).
     */
    private fun checkpoint(vaultId: VaultId, inputs: List<LogEntryInput>, leftOut: List<LeftOutWrite>): List<CheckpointLeaf>? {
        Validation.size(leftOut, 0..Limits.MAX_LEFT_OUT, "/leftOut")
        Validation.unique(leftOut, "/leftOut") { it.nodeId to it.sectionName }
        leftOut.forEachIndexed { index, write -> BlobRules.raw(write.writeHash, BlobRules.KEY_BYTES, "/leftOut/$index/writeHash") }
        val signedRoot = inputs.mapNotNull { it.checkpoint }.singleOrNull()
        if (signedRoot == null) {
            Validation.require(leftOut.isEmpty(), "/leftOut", "unexpected", "Only a request with a checkpoint leaves writes out.")
            return null
        }
        val stored = SectionRepository.leaves(vaultId).associateBy { it.nodeId to it.sectionName }
        for (write in leftOut) {
            val latest = stored[write.nodeId to write.sectionName]
            if (latest?.writeHash != write.writeHash) {
                throw CloakException(
                    CloakErrorCode.CHECKPOINT_CONFLICT,
                    "A write the checkpoint leaves out is no longer the latest of its section; build it again.",
                )
            }
        }
        val excluded = leftOut.map { it.nodeId to it.sectionName }.toSet()
        val leaves = stored.filterKeys { it !in excluded }.values.sortedWith(Merkle.sectionOrder)
        if (Merkle.root(leaves) != signedRoot) {
            throw CloakException(
                CloakErrorCode.CHECKPOINT_CONFLICT,
                "The checkpoint does not match the stored latest writes; build it again.",
            )
        }
        return leaves
    }

    /** Checks the sizes of an entry's binary fields. */
    private fun checkShape(input: LogEntryInput, pointer: String) {
        BlobRules.signature(input.signature, "$pointer/signature")
        BlobRules.optionalKey(input.subjectKeys, "$pointer/subjectKeys")
        BlobRules.optionalKey(input.keyCommitment, "$pointer/keyCommitment")
        BlobRules.optionalKey(input.checkpoint, "$pointer/checkpoint")
        // The encoding cannot tell 32 zero bytes or version 0 from absent: refuse them, so what is
        // stored is exactly what was signed.
        for ((name, value) in listOf("subjectKeys" to input.subjectKeys, "keyCommitment" to input.keyCommitment, "checkpoint" to input.checkpoint)) {
            Validation.require(value == null || !isAbsent(value), "$pointer/$name", "absent", "Omit it rather than send zeros.")
        }
        Validation.require((input.subjectKeyVersion ?: 1) >= 1, "$pointer/subjectKeyVersion", "minimum", "Must be at least 1.")
        Validation.require(input.seq >= 1, "$pointer/seq", "minimum", "Must be at least 1.")
        Validation.require(input.keyVersion >= 1, "$pointer/keyVersion", "minimum", "Must be at least 1.")
        Validation.require(input.authorKeyVersion >= 1, "$pointer/authorKeyVersion", "minimum", "Must be at least 1.")
        // Absent node fields are the nil UUID and the empty string in the signed message (§7.1):
        // refuse those values, so what is stored is exactly what was signed.
        Validation.require(input.nodeId?.value != Uuid.NIL, "$pointer/nodeId", "absent", "Omit it rather than send the nil UUID.")
        Validation.require(input.homeVaultId?.value != Uuid.NIL, "$pointer/homeVaultId", "absent", "Omit it rather than send the nil UUID.")
        Validation.require(input.nodeKey != "", "$pointer/nodeKey", "absent", "Omit it rather than send it empty.")
        Validation.require(input.sections != "", "$pointer/sections", "absent", "Omit it rather than send it empty.")
        Validation.require((input.nodeKey?.length ?: 0) <= NodeKey.MAX_BYTES, "$pointer/nodeKey", "maxLength", "At most 255 bytes.")
        Validation.require((input.sections?.length ?: 0) <= MAX_SECTIONS_FIELD, "$pointer/sections", "maxLength", "Too long.")
    }

    /** Maps a broken rule to the API's error. */
    private fun LogViolation.toException(): CloakException =
        when (reason) {
            "not_authorized" -> neededRole?.let { CloakException.roleRequired(it, "sign this entry") }
                ?: CloakException(CloakErrorCode.LOG_REJECTED, "Entry $seq names a node that is not its author's (not_authorized).")
            "bad_signature", "non_canonical_signature", "non_canonical_key", "small_order_key" ->
                CloakException(CloakErrorCode.BAD_SIGNATURE, "The signature of entry $seq is refused: $reason.")
            "superseded_keys" -> CloakException(
                CloakErrorCode.IDENTITY_VERSION_CONFLICT,
                "Entry $seq uses a key version that was replaced; use the newest keys.",
            )
            else -> CloakException(CloakErrorCode.LOG_REJECTED, "Entry $seq breaks a log rule: $reason.")
        }

    /** Loading a vault's state for the rules. */
    companion object {
        /** Logger of checkpoints that do not read back. */
        private val logger = LoggerFactory.getLogger(LogAppender::class.java)

        /**
         * Builds the log state of a locked vault.
         *
         * @param vault The vault.
         * @param members Its members.
         * @return The state the next request is verified against.
         */
        fun stateOf(vault: VaultRow, members: Map<UserId, MemberRow>): LogState =
            LogState(
                vault.id,
                vault.logSeq,
                vault.logHeadHash,
                vault.keyVersion,
                members.mapValues { it.value.membership },
                NodeLedger(NodeRepository.lookup(vault.id)),
                vault.isDeleted,
            )

        /** Longest `sections` field: every name of 64 characters and a comma, about 100 names. */
        private const val MAX_SECTIONS_FIELD = 6500
    }
}
