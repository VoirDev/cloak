package dev.voir.cloak.server.protocol

import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.SectionScope
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString

/**
 * A user's membership: their role and the key version it commits (`PROTOCOL.md` §7.2).
 *
 * @property role Role in the vault.
 * @property userKeyVersion Committed identity key version; only it carries the member's rights.
 * @property keysDigest `keysDigest` of that version.
 */
internal data class Membership(
    /** Role in the vault. */
    val role: Role,
    /** Committed identity key version. */
    val userKeyVersion: Int,
    /** Digest of that version. */
    val keysDigest: ByteString,
)

/**
 * A vault's state after its last verified entry: what the log rules need.
 *
 * @property vaultId The vault.
 * @property seq `seq` of the last entry; 0 for a vault being created.
 * @property headHash `entryHash` of the last entry; `null` for a vault being created.
 * @property keyVersion Vault key version; 0 for a vault being created.
 * @property members Members by user.
 * @property nodes Nodes created and shared in the vault (§7.7).
 * @property deleted Whether an owner deleted the vault (§12.3).
 */
internal data class LogState(
    /** The vault. */
    val vaultId: VaultId,
    /** `seq` of the last entry. */
    val seq: Long,
    /** `entryHash` of the last entry. */
    val headHash: ByteString?,
    /** Vault key version. */
    val keyVersion: Int,
    /** Members by user. */
    val members: Map<UserId, Membership>,
    /** Nodes created and shared in the vault. */
    val nodes: NodeLedger = NodeLedger(),
    /** Whether an owner deleted the vault. */
    val deleted: Boolean = false,
) {
    /** States of vaults that do not exist yet. */
    companion object {
        /**
         * The state before `vault_created`.
         *
         * @param vaultId The vault being created.
         * @return An empty state.
         */
        fun empty(vaultId: VaultId): LogState = LogState(vaultId, 0, null, 0, emptyMap(), NodeLedger(), false)
    }
}

/**
 * A log entry with its signature, as a request carries it once the server filled in the vault,
 * `seq`, previous hash and author.
 *
 * @property fields The signed fields.
 * @property signature The author's signature blob.
 */
internal data class SignedLogEntry(
    /** The signed fields. */
    val fields: LogFields,
    /** The author's signature blob. */
    val signature: ByteString,
)

/**
 * A rule of `PROTOCOL.md` §7 that a log entry breaks.
 *
 * @property reason Reason as the test vectors name it, such as `not_authorized`.
 * @property seq The entry that breaks it.
 * @property neededRole For `not_authorized`, the role the author needed.
 */
internal class LogViolation(
    /** Reason as the test vectors name it. */
    val reason: String,
    /** The entry that breaks it. */
    val seq: Long,
    /** The role the author needed, for `not_authorized`. */
    val neededRole: Role? = null,
) : Exception("$reason at seq $seq")

/** What the log rules need to know about people's keys. */
internal interface KeyDirectory {
    /**
     * The public keys of a user's key version, when the server holds it with a valid statement.
     *
     * @param userId User.
     * @param keyVersion Key version.
     * @return The keys, or `null`.
     */
    fun keys(userId: UserId, keyVersion: Int): PublicKeys?

    /**
     * Whether a later version of the user's keys exists (`PROTOCOL.md` §5.2). The server checks it
     * when an entry is made; a member only for entries verified after learning of the newer one.
     *
     * @param userId User.
     * @param keyVersion Key version.
     * @return Whether it is superseded.
     */
    fun isSuperseded(userId: UserId, keyVersion: Int): Boolean
}

/**
 * The rules of the vault log (`PROTOCOL.md` §7.2 to §7.6), shared by every request that appends
 * entries. They are the rules every member's client checks, so the server stores nothing a member
 * would refuse; the shared test vectors check that they agree.
 */
internal object LogRules {
    /** Most distinct names one share of a node may hold (`PROTOCOL.md` §7.7). */
    const val MAX_SHARE_NAMES: Int = 1_000

    /** Kinds that may make up a request alone. */
    private val SINGLE_KINDS = setOf(
        LogEntryKind.VAULT_CREATED,
        LogEntryKind.MEMBER_ADDED,
        LogEntryKind.MEMBER_ROLE_SET,
        LogEntryKind.MEMBER_KEYS_REPLACED,
        LogEntryKind.NODE_CREATED,
        LogEntryKind.NODE_SHARED,
        LogEntryKind.NODE_UNSHARED,
        LogEntryKind.VAULT_DELETED,
    )

    /**
     * Applies one request's entries to a vault's state.
     *
     * @param state State before the request; rights are checked in it.
     * @param entries The request's entries, in order.
     * @param keys Key versions the server holds.
     * @return The state after each entry.
     * @throws LogViolation When an entry breaks a rule.
     */
    fun applyRequest(state: LogState, entries: List<SignedLogEntry>, keys: KeyDirectory): List<LogState> {
        require(entries.isNotEmpty()) { "A request appends at least one entry" }
        val before = state.members
        val author = entries.first().fields.authorUserId
        val kinds = mutableListOf<Pair<LogEntryKind, Boolean>>()
        var current = state
        val states = entries.mapIndexed { index, entry ->
            val fields = entry.fields
            current = apply(current, entry, before, keys)
            if (fields.authorUserId != author) throw LogViolation("bad_request_shape", fields.seq)
            kinds += fields.kind to (fields.subjectUserId == author)
            val last = index == entries.lastIndex
            if (fields.requestEnd != last) {
                throw LogViolation(if (last) "unfinished_request" else "bad_request_shape", fields.seq)
            }
            current
        }
        if (!isAllowedShape(kinds)) throw LogViolation("bad_request_shape", entries.last().fields.seq)
        return states
    }

    /** Applies one entry; [before] holds the members before its request. */
    private fun apply(state: LogState, entry: SignedLogEntry, before: Map<UserId, Membership>, keys: KeyDirectory): LogState {
        val e = entry.fields
        val seq = e.seq
        fun fail(reason: String, role: Role? = null): Nothing = throw LogViolation(reason, seq, role)

        // Chain (§7.6 rule 1).
        if (e.vaultId != state.vaultId || seq != state.seq + 1 || e.previousHash != state.headHash) fail("broken_chain")
        if (state.deleted) fail("vault_deleted")
        val message = Messages.logEntry(e)

        // Who signs, with which committed keys (rule 2).
        val authorKeys = keys.keys(e.authorUserId, e.authorKeyVersion) ?: fail("unverified_keys")
        val authorDigest = Messages.keysDigest(authorKeys)
        if (e.kind == LogEntryKind.VAULT_CREATED || e.kind == LogEntryKind.MEMBER_KEYS_REPLACED) {
            if (e.subjectUserId != e.authorUserId || e.subjectKeyVersion != e.authorKeyVersion || e.subjectKeys != authorDigest) {
                fail("unverified_keys")
            }
        } else {
            val membership = state.members[e.authorUserId]
            if (membership?.userKeyVersion != e.authorKeyVersion || membership.keysDigest != authorDigest) fail("unverified_keys")
        }
        StrictEd25519.check(authorKeys.signingPublicKey, message, entry.signature)?.let { fail(it.code) }
        if (keys.isSuperseded(e.authorUserId, e.authorKeyVersion)) fail("superseded_keys")

        // Fields the kind sets (rule 3).
        val rights = before[e.authorUserId]?.role
        val hasCheckpoint = !isAbsent(e.checkpoint)
        val hasSubjectKeys = !isAbsent(e.subjectKeys)
        val present = mapOf(
            "subject" to (e.subjectUserId != null),
            "role" to (e.role != null),
            "subjectKeys" to hasSubjectKeys,
            "keyCommitment" to !isAbsent(e.keyCommitment),
            "node" to (e.nodeId != null),
            "home" to (e.homeVaultId != null),
            "nodeKey" to e.nodeKey.isNotEmpty(),
            "sections" to e.sections.isNotEmpty(),
        )
        val wanted = when (e.kind) {
            LogEntryKind.VAULT_CREATED -> setOf("subject", "role", "subjectKeys", "keyCommitment")
            LogEntryKind.MEMBER_ADDED, LogEntryKind.MEMBER_ROLE_SET -> setOf("subject", "role", "subjectKeys")
            LogEntryKind.MEMBER_REMOVED, LogEntryKind.MEMBER_KEYS_REPLACED -> setOf("subject", "subjectKeys")
            LogEntryKind.KEY_ROTATED -> setOf("keyCommitment")
            LogEntryKind.NODE_CREATED -> setOf("node", "nodeKey")
            LogEntryKind.NODE_SHARED -> setOf("node", "home", "nodeKey", "sections")
            LogEntryKind.NODE_UNSHARED -> setOf("node", "sections")
            LogEntryKind.VAULT_DELETED -> emptySet()
        }
        val fieldsMatch = present.all { (field, isPresent) -> isPresent == (field in wanted) } &&
            hasSubjectKeys == ((e.subjectKeyVersion ?: 0) > 0)

        val members = state.members.toMutableMap()
        val subjectId = e.subjectUserId
        val subject = subjectId?.let(state.members::get)
        val committed = subject != null && subject.keysDigest == e.subjectKeys && subject.userKeyVersion == e.subjectKeyVersion
        var keyVersion = state.keyVersion
        var nodes = state.nodes
        var deleted = false

        when (e.kind) {
            LogEntryKind.VAULT_CREATED -> {
                if (seq != 1L || e.role != Role.OWNER || e.keyVersion != 1 || hasCheckpoint) fail("bad_request_shape")
                if (!fieldsMatch) fail("unexpected_field")
                members[e.authorUserId] = Membership(Role.OWNER, e.authorKeyVersion, authorDigest)
                keyVersion = 1
            }
            LogEntryKind.MEMBER_ADDED -> {
                if (!fieldsMatch || hasCheckpoint) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                val role = checkNotNull(e.role)
                if (subjectId == null || subject != null) fail("invalid_entry")
                val needed = if (role == Role.OWNER) Role.OWNER else Role.ADMIN
                if (rights?.includes(needed) != true) fail("not_authorized", needed)
                val subjectVersion = checkNotNull(e.subjectKeyVersion)
                val subjectKeys = keys.keys(subjectId, subjectVersion)
                if (subjectKeys == null || Messages.keysDigest(subjectKeys) != e.subjectKeys) fail("unverified_keys")
                if (keys.isSuperseded(subjectId, subjectVersion)) fail("superseded_keys")
                members[subjectId] = Membership(role, subjectVersion, checkNotNull(e.subjectKeys))
            }
            LogEntryKind.MEMBER_ROLE_SET -> {
                if (!fieldsMatch) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                val role = checkNotNull(e.role)
                if (subjectId == null || subject == null || !committed || subject.role == role) fail("invalid_entry")
                if (keys.isSuperseded(subjectId, subject.userKeyVersion)) fail("superseded_keys")
                val lowersSelf = subjectId == e.authorUserId && !role.includes(subject.role)
                val needed = if (subject.role == Role.OWNER || role == Role.OWNER) Role.OWNER else Role.ADMIN
                if (!lowersSelf && rights?.includes(needed) != true) fail("not_authorized", needed)
                val losesWrite = subject.role.includes(Role.EDITOR) && !role.includes(Role.EDITOR)
                if (losesWrite && !hasCheckpoint) fail("missing_checkpoint")
                if (!losesWrite && hasCheckpoint) fail("unexpected_field")
                members[subjectId] = subject.copy(role = role)
                if (members.values.none { it.role == Role.OWNER }) fail("no_owner")
            }
            LogEntryKind.MEMBER_REMOVED -> {
                if (!fieldsMatch) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                if (subjectId == null || subject == null || !committed) fail("invalid_entry")
                if (subjectId == e.authorUserId) {
                    val needsCheckpoint = subject.role.includes(Role.EDITOR)
                    if (needsCheckpoint && !hasCheckpoint) fail("missing_checkpoint")
                    if (!needsCheckpoint && hasCheckpoint) fail("unexpected_field")
                } else {
                    if (hasCheckpoint) fail("unexpected_field")
                    val needed = if (subject.role == Role.OWNER) Role.OWNER else Role.ADMIN
                    if (rights?.includes(needed) != true) fail("not_authorized", needed)
                }
                members.remove(subjectId)
                if (members.values.none { it.role == Role.OWNER }) fail("no_owner")
                // A share ends when its owner stops being a member (§7.7).
                nodes = nodes.withoutSharesOf(subjectId)
            }
            LogEntryKind.MEMBER_KEYS_REPLACED -> {
                if (!fieldsMatch) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                val current = state.members[e.authorUserId] ?: fail("invalid_entry")
                val newVersion = checkNotNull(e.subjectKeyVersion)
                if (newVersion <= current.userKeyVersion) fail("unverified_keys")
                // The committed version must be the one the chain starts from, and every version up
                // to the new one must be held with a valid statement (§5.2).
                val start = keys.keys(e.authorUserId, current.userKeyVersion)
                if (start == null || Messages.keysDigest(start) != current.keysDigest) fail("unverified_keys")
                for (version in current.userKeyVersion + 1..newVersion) {
                    if (keys.keys(e.authorUserId, version) == null) fail("unverified_keys")
                }
                val needsCheckpoint = current.role.includes(Role.EDITOR)
                if (needsCheckpoint && !hasCheckpoint) fail("missing_checkpoint")
                if (!needsCheckpoint && hasCheckpoint) fail("unexpected_field")
                members[e.authorUserId] = current.copy(userKeyVersion = newVersion, keysDigest = authorDigest)
            }
            LogEntryKind.KEY_ROTATED -> {
                if (!fieldsMatch) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion + 1) fail("bad_request_shape")
                if (!hasCheckpoint) fail("missing_checkpoint")
                if (rights?.includes(Role.ADMIN) != true) fail("not_authorized", Role.ADMIN)
                keyVersion += 1
            }
            LogEntryKind.NODE_CREATED -> {
                if (!fieldsMatch || hasCheckpoint) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                val nodeId = checkNotNull(e.nodeId)
                if (!NodeKey.isValid(e.nodeKey) || nodes.createdNode(nodeId) != null) fail("invalid_entry")
                if (rights?.includes(Role.EDITOR) != true) fail("not_authorized", Role.EDITOR)
                val origin = NodeOrigin(e.authorUserId, state.vaultId, NodeKey(e.nodeKey))
                // Only the user the node derives from may create it (§7.7).
                if (origin.nodeId != nodeId) fail("not_authorized")
                nodes = nodes.withCreated(nodeId, CreatedNode(e.authorUserId, origin.nodeKey, seq))
            }
            LogEntryKind.NODE_SHARED -> {
                if (!fieldsMatch || hasCheckpoint) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                val nodeId = checkNotNull(e.nodeId)
                val home = checkNotNull(e.homeVaultId)
                val scope = SectionScope.parse(e.sections)
                if (scope == null || home == state.vaultId || !NodeKey.isValid(e.nodeKey)) fail("invalid_entry")
                val before = nodes.share(nodeId)
                var all = before?.all
                val names = before?.names.orEmpty().toMutableMap()
                when (scope) {
                    SectionScope.All -> if (all == null) all = seq
                    is SectionScope.Names -> scope.names.forEach { name -> if (all == null && name !in names) names[name] = seq }
                }
                // A share holds at most MAX_SHARE_NAMES distinct names, so the place rule and the
                // host's checks read a bounded set; past it, share with `*` instead.
                if (names.size > MAX_SHARE_NAMES) fail("invalid_entry")
                if (rights?.includes(Role.ADMIN) != true) fail("not_authorized", Role.ADMIN)
                val origin = NodeOrigin(e.authorUserId, home, NodeKey(e.nodeKey))
                if (origin.nodeId != nodeId) fail("not_authorized")
                nodes = nodes.withShare(nodeId, NodeShare(e.authorUserId, home, origin.nodeKey, all, names))
            }
            LogEntryKind.NODE_UNSHARED -> {
                if (!fieldsMatch || hasCheckpoint) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                val nodeId = checkNotNull(e.nodeId)
                val scope = SectionScope.parse(e.sections)
                val share = nodes.share(nodeId)
                if (scope == null || share == null) fail("invalid_entry")
                if (rights?.includes(Role.ADMIN) != true && e.authorUserId != share.ownerUserId) fail("not_authorized", Role.ADMIN)
                nodes = when (scope) {
                    SectionScope.All -> nodes.withShare(nodeId, null)
                    is SectionScope.Names -> {
                        if (share.all != null || scope.names.any { it !in share.names }) fail("invalid_entry")
                        val names = share.names - scope.names.toSet()
                        nodes.withShare(nodeId, if (names.isEmpty()) null else share.copy(names = names))
                    }
                }
            }
            LogEntryKind.VAULT_DELETED -> {
                if (!fieldsMatch || hasCheckpoint) fail("unexpected_field")
                if (seq == 1L || e.keyVersion != state.keyVersion) fail("bad_request_shape")
                if (rights?.includes(Role.OWNER) != true) fail("not_authorized", Role.OWNER)
                deleted = true
            }
        }
        return LogState(state.vaultId, seq, sha256(message), keyVersion, members, nodes, deleted)
    }

    /** Whether a request's kinds form one of §7.3's shapes; each pair is a kind and whether its subject is the author. */
    private fun isAllowedShape(kinds: List<Pair<LogEntryKind, Boolean>>): Boolean {
        val (lastKind, lastSelf) = kinds.last()
        if (kinds.size == 1 && (lastKind in SINGLE_KINDS || (lastKind == LogEntryKind.MEMBER_REMOVED && lastSelf))) return true
        return lastKind == LogEntryKind.KEY_ROTATED &&
            kinds.dropLast(1).all { (kind, self) -> kind == LogEntryKind.MEMBER_REMOVED && !self }
    }
}
