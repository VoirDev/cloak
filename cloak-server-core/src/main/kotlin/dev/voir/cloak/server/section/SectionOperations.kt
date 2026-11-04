package dev.voir.cloak.server.section

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.DatabaseKeyDirectory
import dev.voir.cloak.server.identity.IdentityOperations
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.paging.KeysetCursor
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.protocol.Membership
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.SectionWriteFields
import dev.voir.cloak.server.protocol.sha256
import dev.voir.cloak.server.protocol.isAbsent
import dev.voir.cloak.server.section.domain.BatchWriteItem
import dev.voir.cloak.server.section.domain.SectionHeaderPage
import dev.voir.cloak.server.section.domain.SectionPage
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.section.domain.SectionRemoval
import dev.voir.cloak.server.section.domain.SectionWrite
import dev.voir.cloak.server.section.domain.SectionWriteInput
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.persistence.SectionRepository
import dev.voir.cloak.server.vault.persistence.NodeRepository
import dev.voir.cloak.server.vault.VaultAccess
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import dev.voir.cloak.server.vault.persistence.VaultRow
import kotlin.time.Instant

/**
 * Sections: encrypted parts of nodes, written and read per vault (`/vaults/{vaultId}/sections`,
 * `/sections/batch-write`).
 *
 * A write locks its vault's row, so writes of one vault, its log appends and rotations run one at
 * a time: a checkpoint always covers the writes stored before it, and change numbers commit in
 * order, so a client that reads `afterChange` never skips a write.
 *
 * @property context Database and clock.
 */
public class SectionOperations internal constructor(
    private val context: CloakContext,
) {
    /**
     * Creates, changes or deletes a section with one signed write (`PROTOCOL.md` §8.3).
     *
     * @param caller Authenticated user; an editor or stronger of the vault.
     * @param section The section.
     * @param input The signed write.
     * @return The stored write.
     * @throws CloakException `not_found`, `role_required`, `stale_head`, `vault_key_version_mismatch`,
     *   `version_conflict`, `identity_version_conflict`, `bad_signature`, `payload_too_large`,
     *   `validation_failed` (rule `max_sections` when the write would make one more section live than
     *   the vault's limit, rule `max_stored_sections` when a new section would exceed the stored
     *   limit), `busy` while a write pause holds the vault (`PROTOCOL.md` §7.5).
     */
    public fun write(caller: UserId, section: SectionRef, input: SectionWriteInput): SectionWrite = context.operation("writeSection") {
        batchWrite(caller, listOf(BatchWriteItem(section, input)), pointerOf = { "" }).single()
    }

    /**
     * Writes up to 100 sections in any of the caller's vaults, together or not at all: the
     * sections of one record, or a move (a deletion in one vault and a first write in another).
     *
     * @param caller Authenticated user.
     * @param items The writes; each section at most once.
     * @return The stored writes, in request order.
     * @throws CloakException The errors of [write], for the first item that fails.
     */
    public fun batchWrite(caller: UserId, items: List<BatchWriteItem>): List<SectionWrite> = context.operation("batchWriteSections") {
        batchWrite(caller, items) { "/items/$it" }
    }

    /**
     * Reads a section's latest write.
     *
     * @param caller Authenticated user; any member of the vault.
     * @param section The section.
     * @return The latest write, deletions included.
     * @throws CloakException `not_found` unless the caller is a member and the section was written.
     */
    public fun get(caller: UserId, section: SectionRef): SectionWrite = context.operation("getSection") {
        asCaller(caller) {
            VaultAccess.readAsMember(caller, section.vaultId)
            SectionRepository.find(section) ?: throw CloakException.notFound("section")
        }
    }

    /**
     * Lists a vault's sections by the change number of their latest write, deletions included.
     *
     * @param caller Authenticated user; any member of the vault.
     * @param vaultId The vault.
     * @param afterChange Only sections whose latest write came after this change number; `null` for all.
     * @param limit Page size.
     * @return One page of writes and removals, the last change number it covers and the vault's latest.
     */
    public fun list(caller: UserId, vaultId: VaultId, afterChange: Long? = null, limit: Int = PageRequest.DEFAULT_LIMIT): SectionPage = context.operation("listVaultSections") {
        KeysetCursor.checkLimit(limit)
        Validation.require((afterChange ?: 1) >= 1, "#/query/afterChange", "minimum", "Must be at least 1.")
        asCaller(caller) {
            val (vault, _) = VaultAccess.readAsMember(caller, vaultId)
            val after = afterChange ?: 0
            val writes = SectionRepository.pageByChange(vaultId, after, limit)
            val removals = SectionRepository.removalsByChange(vaultId, after, limit)
            val through = throughChange(vault.changeSeq, limit, writes.map { it.changeSeq }, removals)
            SectionPage(writes.filter { it.changeSeq <= through }, removals.filter { it.changeSeq <= through }, through, vault.changeSeq)
        }
    }

    /**
     * Lists a vault's section headers by the change number of their latest write, deletions
     * included: the writes without their ciphertext, enough to check signatures and standing
     * (`PROTOCOL.md` §8.4). The ciphertext is never read.
     *
     * @param caller Authenticated user; any member of the vault.
     * @param vaultId The vault.
     * @param afterChange Only sections whose latest write came after this change number; `null` for all.
     * @param limit Page size, up to [PageRequest.MAX_INDEX_LIMIT].
     * @return One page of headers and removals, the last change number it covers and the vault's latest.
     */
    public fun headers(
        caller: UserId,
        vaultId: VaultId,
        afterChange: Long? = null,
        limit: Int = PageRequest.MAX_INDEX_LIMIT,
    ): SectionHeaderPage = context.operation("listVaultSectionHeaders") {
        KeysetCursor.checkLimit(limit, PageRequest.MAX_INDEX_LIMIT)
        Validation.require((afterChange ?: 1) >= 1, "#/query/afterChange", "minimum", "Must be at least 1.")
        asCaller(caller) {
            val (vault, _) = VaultAccess.readAsMember(caller, vaultId)
            val after = afterChange ?: 0
            val headers = SectionRepository.headersByChange(vaultId, after, limit)
            val removals = SectionRepository.removalsByChange(vaultId, after, limit)
            val through = throughChange(vault.changeSeq, limit, headers.map { it.changeSeq }, removals)
            SectionHeaderPage(headers.filter { it.changeSeq <= through }, removals.filter { it.changeSeq <= through }, through, vault.changeSeq)
        }
    }

    /** Validates, locks the vaults in id order, then applies each write in request order. */
    private fun CloakContext.OperationScope.batchWrite(
        caller: UserId,
        items: List<BatchWriteItem>,
        pointerOf: (Int) -> String,
    ): List<SectionWrite> {
        Validation.size(items, 1..Limits.MAX_BATCH_SIZE, "/items")
        Validation.unique(items, "/items") { it.section }
        items.forEachIndexed { index, item -> checkShape(item.input, pointerOf(index)) }
        return asCaller(caller) {
            val vaultIds = items.map { it.section.vaultId }.toSet()
            // Membership first, without locks: a non-member cannot hold other vaults locked.
            if (!MemberRepository.roles(caller, vaultIds).keys.containsAll(vaultIds)) throw CloakException.notFound("vault")
            val vaults = VaultRepository.lock(vaultIds).toMutableMap()
            // A deleted vault takes no more writes (§12.3).
            if (vaults.values.any { it.isDeleted }) throw CloakException.notFound("vault")
            val memberships = vaultIds.associateWith { MemberRepository.find(it, caller) }
            val keys = DatabaseKeyDirectory()
            val now = context.clock.now()
            // A pause holds every section write, its holder's too, until the checkpoint is in. It
            // usually ends within a second, when the paused request is applied, so writers are
            // told to try again soon rather than to sit out its whole length.
            vaults.values.forEach { vault ->
                vault.pause?.takeIf { it.holdsAt(now) }?.let {
                    throw CloakException.paused(minOf(secondsUntil(now, it.until), MAX_PAUSE_RETRY_AFTER_SECONDS))
                }
            }
            val written = items.mapIndexed { index, item ->
                val vault = vaults[item.section.vaultId] ?: throw CloakException.notFound("vault")
                val membership = memberships[vault.id]?.membership ?: throw CloakException.notFound("vault")
                val (write, counts) = apply(caller, vault, membership, item, keys, now, pointerOf(index))
                vaults[vault.id] = counts.copy(changeSeq = write.changeSeq)
                write
            }
            vaults.values.filter { it.id in vaultIds }.forEach(VaultRepository::updateSections)
            written
        }
    }

    /** Checks one write against its locked vault and stores it; also returns the vault's new section counts. */
    private fun apply(
        caller: UserId,
        vault: VaultRow,
        membership: Membership,
        item: BatchWriteItem,
        keys: DatabaseKeyDirectory,
        now: Instant,
        pointer: String,
    ): Pair<SectionWrite, VaultRow> {
        val input = item.input
        if (!membership.role.includes(Role.EDITOR)) throw CloakException.roleRequired(Role.EDITOR, "write sections")
        if (input.writerKeyVersion != membership.userKeyVersion || keys.isSuperseded(caller, membership.userKeyVersion)) {
            throw CloakException(
                CloakErrorCode.IDENTITY_VERSION_CONFLICT,
                "Sign with your committed key version, and record a key replacement in this vault first.",
                currentVersion = membership.userKeyVersion.toLong(),
            )
        }
        if (input.logSeq != vault.logSeq || input.logHeadHash != vault.logHeadHash) {
            throw CloakException(
                CloakErrorCode.STALE_HEAD,
                "The vault log is at ${vault.logSeq}; verify it and cite its head.",
                currentVersion = vault.logSeq,
            )
        }
        if (input.vaultKeyVersion != vault.keyVersion) {
            throw CloakException(
                CloakErrorCode.VAULT_KEY_VERSION_MISMATCH,
                "The vault key is at version ${vault.keyVersion}.",
                currentVersion = vault.keyVersion.toLong(),
            )
        }
        val latest = SectionRepository.find(item.section)
        if (input.dataVersion != (latest?.input?.dataVersion ?: 0) + 1 || input.previousWriteHash != latest?.writeHash) {
            throw CloakException(
                CloakErrorCode.VERSION_CONFLICT,
                "The section was written by someone else since you read it.",
                currentVersion = latest?.input?.dataVersion ?: 0,
            )
        }
        if (input.deleted && (latest == null || latest.input.deleted)) throw CloakException.notFound("section")
        // A deletion stays stored without content; only live sections bound a checkpoint (§7.5).
        val becomesLive = !input.deleted && (latest == null || latest.input.deleted)
        val maxStored = context.settings.maxStoredSectionsPerVault
        Validation.require(
            !becomesLive || vault.liveSections < Limits.MAX_SECTIONS_PER_VAULT,
            pointer,
            "max_sections",
            "The vault has ${Limits.MAX_SECTIONS_PER_VAULT} live sections already.",
        )
        Validation.require(
            latest != null || vault.storedSections < maxStored,
            pointer,
            "max_stored_sections",
            "The vault stores $maxStored sections already, deleted ones included.",
        )
        Validation.require(
            latest == null || latest.input.nodeType == input.nodeType,
            "$pointer/nodeType",
            "node_type",
            "Must stay ${latest?.input?.nodeType?.value}.",
        )
        val origin = requirePlace(item.section, input, pointer)
        val fields = SectionWriteFields(
            vaultId = item.section.vaultId,
            nodeId = item.section.nodeId,
            nodeType = input.nodeType,
            origin = origin,
            sectionName = item.section.sectionName,
            vaultKeyVersion = input.vaultKeyVersion,
            dataVersion = input.dataVersion,
            deleted = input.deleted,
            logSeq = input.logSeq,
            logHeadHash = input.logHeadHash,
            previousWriteHash = input.previousWriteHash,
            writerUserId = caller,
            writerKeyVersion = input.writerKeyVersion,
            ciphertextHash = input.ciphertext?.let(::sha256),
        )
        val message = Messages.sectionWrite(fields)
        val writer = checkNotNull(keys.keys(caller, input.writerKeyVersion))
        IdentityOperations.requireSignature(writer.signingPublicKey, message, input.signature, "$pointer/signature")
        val write = SectionWrite(item.section, input, caller, fields.ciphertextHash, sha256(message), vault.changeSeq + 1, now)
        SectionRepository.upsert(write)
        val counts = vault.copy(
            liveSections = vault.liveSections + (if (becomesLive) 1 else 0) - (if (input.deleted) 1 else 0),
            storedSections = vault.storedSections + if (latest == null) 1 else 0,
        )
        return write to counts
    }

    /**
     * Checks where a write's node lives (`PROTOCOL.md` §8.4 rule 6): a write with content is stored
     * only if its node derives from its owner, home and key, and lives in the vault since no later
     * than the write's head: created there, its home, or shared there by name or with `*`, with the
     * owner, home and key the entry recorded. A deletion carries nothing to read, so its place is not
     * judged, but its node must still derive from its origin.
     *
     * @return The write's node origin, as signed.
     * @throws CloakException `validation_failed`, rule `bad_node` for a node that does not derive
     *   from its origin, rule `not_shared` for one that does not live in the vault.
     */
    private fun requirePlace(section: SectionRef, input: SectionWriteInput, pointer: String): NodeOrigin {
        Validation.require(NodeKey.isValid(input.nodeKey), "$pointer/nodeKey", "node_key", "Must be 1 to 255 bytes of UTF-8.")
        val origin = NodeOrigin(input.ownerUserId, input.homeVaultId, NodeKey(input.nodeKey))
        Validation.require(
            origin.nodeId == section.nodeId,
            "$pointer/nodeKey",
            "bad_node",
            "The node id must derive from its owner, home vault and key.",
        )
        // A deletion carries nothing to read, so where it stands is not judged; its origin is.
        if (input.deleted) return origin
        val lives = if (origin.homeVaultId == section.vaultId) {
            val node = NodeRepository.createdNode(section.vaultId, section.nodeId)
            node != null && node.ownerUserId == origin.ownerUserId && node.nodeKey == origin.nodeKey && node.seq <= input.logSeq
        } else {
            val share = NodeRepository.share(section.vaultId, section.nodeId)
            val since = share?.since(section.sectionName)
            share != null && share.ownerUserId == origin.ownerUserId && share.homeVaultId == origin.homeVaultId &&
                share.nodeKey == origin.nodeKey && since != null && since <= input.logSeq
        }
        Validation.require(
            lives,
            "$pointer/nodeId",
            "not_shared",
            "The node is not created in this vault, nor is the section shared into it.",
        )
        return origin
    }

    /** Checks the request shape of one write. */
    private fun checkShape(input: SectionWriteInput, pointer: String) {
        BlobRules.signature(input.signature, "$pointer/signature")
        BlobRules.raw(input.logHeadHash, BlobRules.KEY_BYTES, "$pointer/logHeadHash")
        BlobRules.optionalKey(input.previousWriteHash, "$pointer/previousWriteHash")
        Validation.require(!isAbsentDigest(input.previousWriteHash), "$pointer/previousWriteHash", "absent", "Omit it rather than send zeros.")
        Validation.require(input.dataVersion >= 1, "$pointer/dataVersion", "minimum", "Must be at least 1.")
        Validation.require(input.logSeq >= 1, "$pointer/logSeq", "minimum", "Must be at least 1.")
        Validation.require(
            input.deleted == (input.ciphertext == null),
            "$pointer/ciphertext",
            "deletion",
            "A deletion has no ciphertext, and any other write has one.",
        )
        input.ciphertext?.let { BlobRules.ciphertext(it, "$pointer/ciphertext") }
    }
}

/**
 * The last change number a page covers: everything up to the vault's latest, unless the writes or
 * the removals filled their page, which then ends at the lower of their last change numbers, so no
 * change in between is skipped.
 */
private fun throughChange(latest: Long, limit: Int, writes: List<Long>, removals: List<SectionRemoval>): Long =
    minOf(
        latest,
        writes.takeIf { it.size >= limit }?.last() ?: Long.MAX_VALUE,
        removals.takeIf { it.size >= limit }?.last()?.changeSeq ?: Long.MAX_VALUE,
    )

/** Longest `Retry-After` of a write refused by a pause: the pause usually ends far sooner than it runs out. */
private const val MAX_PAUSE_RETRY_AFTER_SECONDS: Int = 2

/** Whole seconds from [now] until [until], at least 1, for a `Retry-After`. */
internal fun secondsUntil(now: Instant, until: Instant): Int =
    ((until - now).inWholeMilliseconds + 999).div(1000).coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()

/** Whether a present 32-byte value is all zeros, which the encoding cannot tell from absent. */
private fun isAbsentDigest(value: kotlinx.io.bytestring.ByteString?): Boolean = value != null && isAbsent(value)
