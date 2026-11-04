package dev.voir.cloak.server.vault.domain

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeId
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * One signed log entry as a client sends it (`PROTOCOL.md` §7.1). The server fills in the vault,
 * the previous hash and the author, rebuilds the message and checks the signature.
 *
 * @property seq Position the entry claims.
 * @property kind Kind of entry.
 * @property subjectUserId User subject.
 * @property role Role set.
 * @property keyVersion Vault key version once the entry applies.
 * @property subjectKeys `keysDigest` of the subject's keys.
 * @property subjectKeyVersion The subject's identity key version.
 * @property keyCommitment Commitment of a new key version.
 * @property checkpoint Merkle root over the vault's latest writes.
 * @property requestEnd Whether the entry ends its request.
 * @property authorKeyVersion The author's identity key version that signs.
 * @property signature The author's signature.
 * @property nodeId Node a node entry creates, shares or takes back.
 * @property homeVaultId Home vault of the node `node_shared` shares.
 * @property nodeKey Key of the node `node_created` creates or `node_shared` shares.
 * @property sections Names a node entry covers: `*`, or names ascending and comma-joined.
 */
public data class LogEntryInput(
    /** Position the entry claims. */
    public val seq: Long,
    /** Kind of entry. */
    public val kind: LogEntryKind,
    /** User subject. */
    public val subjectUserId: UserId?,
    /** Role set. */
    public val role: Role?,
    /** Vault key version once the entry applies. */
    public val keyVersion: Int,
    /** Digest of the subject's keys. */
    public val subjectKeys: ByteString?,
    /** The subject's key version. */
    public val subjectKeyVersion: Int?,
    /** Commitment of a new key version. */
    public val keyCommitment: ByteString?,
    /** Merkle root over the latest writes. */
    public val checkpoint: ByteString?,
    /** Whether the entry ends its request. */
    public val requestEnd: Boolean,
    /** The author's key version. */
    public val authorKeyVersion: Int,
    /** The author's signature. */
    public val signature: ByteString,
    /** Node a node entry creates, shares or takes back. */
    public val nodeId: NodeId? = null,
    /** Home vault of the node `node_shared` shares. */
    public val homeVaultId: VaultId? = null,
    /** Key of the node a node entry names. */
    public val nodeKey: String? = null,
    /** Names a node entry covers. */
    public val sections: String? = null,
)

/**
 * A stored log entry.
 *
 * @property vaultId Vault.
 * @property input The signed fields and signature as the author sent them.
 * @property authorUserId Author.
 * @property entryHash SHA-256 of the signed message, which includes the previous entry's hash.
 * @property createdAt Instant the entry was appended.
 */
public data class LogEntry(
    /** Vault. */
    public val vaultId: VaultId,
    /** The signed fields and signature. */
    public val input: LogEntryInput,
    /** Author. */
    public val authorUserId: UserId,
    /** SHA-256 of the signed message. */
    public val entryHash: ByteString,
    /** Instant the entry was appended. */
    public val createdAt: Instant,
)

/**
 * One page of a vault's log.
 *
 * @property items Entries, oldest first.
 * @property headSeq The log's last `seq`; read on while the last item is before it.
 */
public data class VaultLogPage(
    /** Entries, oldest first. */
    public val items: List<LogEntry>,
    /** The log's last `seq`. */
    public val headSeq: Long,
)

/**
 * One vault a batch read asks for (`POST /vaults/batch-get`).
 *
 * @property vaultId The vault.
 * @property afterSeq Log entries after this `seq`; `null` for all.
 */
public data class VaultLogQuery(
    /** The vault. */
    public val vaultId: VaultId,
    /** Log entries after this `seq`. */
    public val afterSeq: Long? = null,
)

/**
 * The answer for one vault of a batch read: its view and one page of its log, or neither when the
 * caller cannot see it.
 *
 * @property vaultId The vault asked.
 * @property vault The vault as the caller sees it; `null` when it is not found.
 * @property log One page of its log after the asked `seq`; `null` when it is not found.
 */
public data class VaultLogBatchItem(
    /** The vault asked. */
    public val vaultId: VaultId,
    /** The vault as the caller sees it. */
    public val vault: Vault?,
    /** One page of its log. */
    public val log: VaultLogPage?,
) {
    /** Whether the caller can see the vault. */
    public val found: Boolean get() = vault != null
}
