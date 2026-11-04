package dev.voir.cloak.server.protocol

import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString

/**
 * The fields of a vault log entry's signed message (`PROTOCOL.md` §7.1), as the server rebuilds
 * them from the request and its stored state. Absent values are `null`.
 *
 * @property vaultId Vault whose log the entry extends.
 * @property seq Position in the log, from 1.
 * @property previousHash `entryHash` of the previous entry; `null` for `seq` 1.
 * @property kind Kind of entry.
 * @property subjectUserId User the entry is about.
 * @property role Role the entry sets.
 * @property keyVersion Vault key version once the entry applies.
 * @property subjectKeys `keysDigest` of the subject's keys.
 * @property subjectKeyVersion The subject's identity key version.
 * @property keyCommitment Commitment of the key version the entry creates.
 * @property checkpoint Merkle root over the vault's latest writes.
 * @property requestEnd Whether the entry ends its request.
 * @property authorUserId Author, who signs.
 * @property authorKeyVersion The author's identity key version that signs.
 * @property nodeId Node a node entry names (`PROTOCOL.md` §7.7); `null` when absent.
 * @property homeVaultId Home vault of the node `node_shared` shares; `null` when absent.
 * @property nodeKey Key of the node a node entry names; empty when absent.
 * @property sections Names a node entry covers; empty when absent.
 */
internal data class LogFields(
    /** Vault whose log the entry extends. */
    val vaultId: VaultId,
    /** Position in the log. */
    val seq: Long,
    /** Hash of the previous entry. */
    val previousHash: ByteString?,
    /** Kind of entry. */
    val kind: LogEntryKind,
    /** User subject. */
    val subjectUserId: UserId?,
    /** Role set. */
    val role: Role?,
    /** Vault key version once the entry applies. */
    val keyVersion: Int,
    /** Digest of the subject's keys. */
    val subjectKeys: ByteString?,
    /** The subject's key version. */
    val subjectKeyVersion: Int?,
    /** Commitment of a new key version. */
    val keyCommitment: ByteString?,
    /** Merkle root over the latest writes. */
    val checkpoint: ByteString?,
    /** Whether the entry ends its request. */
    val requestEnd: Boolean,
    /** Author. */
    val authorUserId: UserId,
    /** The author's key version. */
    val authorKeyVersion: Int,
    /** Node a node entry names. */
    val nodeId: NodeId? = null,
    /** Home vault of a shared node. */
    val homeVaultId: VaultId? = null,
    /** Key of the node; empty when absent. */
    val nodeKey: String = "",
    /** Names a node entry covers; empty when absent. */
    val sections: String = "",
)

/**
 * The fields of a section write's signed message (`PROTOCOL.md` §8.2).
 *
 * @property vaultId Vault the section lives in.
 * @property nodeId Node of the section.
 * @property nodeType App-defined node type.
 * @property origin The node's owner, home vault and key, which derive its id (`PROTOCOL.md` §8.1).
 * @property sectionName Section name.
 * @property vaultKeyVersion Vault key version that encrypts the content.
 * @property dataVersion Version this write creates.
 * @property deleted Whether the write deletes the section.
 * @property logSeq Log head the writer verified.
 * @property logHeadHash `entryHash` of that head.
 * @property previousWriteHash `writeHash` of the previous write; `null` for the first.
 * @property writerUserId Writer.
 * @property writerKeyVersion The writer's identity key version that signs.
 * @property ciphertextHash SHA-256 of the section ciphertext, which the message signs in its place;
 *   `null` for a deletion. A write's header carries it, so the message is rebuilt without the ciphertext.
 */
internal data class SectionWriteFields(
    /** Vault the section lives in. */
    val vaultId: VaultId,
    /** Node of the section. */
    val nodeId: NodeId,
    /** App-defined node type. */
    val nodeType: NodeType,
    /** The node's owner, home and key (§8.1). */
    val origin: NodeOrigin,
    /** Section name. */
    val sectionName: SectionName,
    /** Vault key version of the content. */
    val vaultKeyVersion: Int,
    /** Version this write creates. */
    val dataVersion: Long,
    /** Whether the write deletes the section. */
    val deleted: Boolean,
    /** Log head the writer verified. */
    val logSeq: Long,
    /** Hash of that head. */
    val logHeadHash: ByteString,
    /** Hash of the previous write. */
    val previousWriteHash: ByteString?,
    /** Writer. */
    val writerUserId: UserId,
    /** The writer's key version. */
    val writerKeyVersion: Int,
    /** SHA-256 of the ciphertext. */
    val ciphertextHash: ByteString?,
)

/** Canonical messages that clients sign and the server verifies (`PROTOCOL.md` §5, §7, §8). */
internal object Messages {
    /**
     * Builds a key version's fingerprint message (§5.1).
     *
     * @param keys The key version.
     * @return Canonical message.
     */
    fun fingerprint(keys: PublicKeys): ByteString =
        Canonical()
            .label("cloak/v1/fingerprint")
            .uuid(keys.userId.value)
            .u8(keys.cryptoSuite)
            .u32(keys.keyVersion)
            .key32(keys.encryptionPublicKey)
            .key32(keys.signingPublicKey)
            .key32(keys.recoverySigningPublicKey)
            .build()

    /**
     * Digests a key version: how the vault log commits to a person's keys.
     *
     * @param keys The key version.
     * @return `SHA-256(fingerprintMessage)`.
     */
    fun keysDigest(keys: PublicKeys): ByteString = sha256(fingerprint(keys))

    /**
     * Builds a key statement's message (§5.2).
     *
     * @param keys The key version it publishes.
     * @param previousKeysDigest `keysDigest` of the version it follows; `null` for version 1.
     * @return Canonical message.
     */
    fun keyStatement(keys: PublicKeys, previousKeysDigest: ByteString?): ByteString =
        Canonical()
            .label("cloak/v1/key-statement")
            .uuid(keys.userId.value)
            .u32(keys.keyVersion)
            .digest32(keysDigest(keys))
            .digest32(previousKeysDigest)
            .build()

    /**
     * Builds the statement a new private key bundle is signed with (§5.4).
     *
     * @param userId The user.
     * @param keyVersion The current identity key version, whose signing key signs.
     * @param credentialsVersion The version the change creates.
     * @param privateKeyBundle The new bundle.
     * @param kdf Its Argon2id parameters.
     * @return Canonical message.
     */
    fun credentials(userId: UserId, keyVersion: Int, credentialsVersion: Int, privateKeyBundle: ByteString, kdf: KdfParams): ByteString =
        Canonical()
            .label("cloak/v1/credentials")
            .uuid(userId.value)
            .u32(keyVersion)
            .u32(credentialsVersion)
            .digest32(sha256(privateKeyBundle))
            .digest32(sha256(kdf.salt))
            .u32(kdf.memoryKib)
            .u32(kdf.iterations)
            .u8(kdf.parallelism)
            .build()

    /**
     * Builds the statement a user signs to delete their own identity (§5.7).
     *
     * @param userId The user.
     * @param keyVersion The current identity key version.
     * @param credentialsVersion The current credentials version.
     * @param notAfter Unix seconds after which the statement is refused.
     * @return Canonical message.
     */
    fun identityDeletion(userId: UserId, keyVersion: Int, credentialsVersion: Int, notAfter: Long): ByteString =
        Canonical()
            .label("cloak/v1/identity-deletion")
            .uuid(userId.value)
            .u32(keyVersion)
            .u32(credentialsVersion)
            .u64(notAfter)
            .build()

    /**
     * Builds a log entry's signed message (§7.1).
     *
     * @param fields Entry fields.
     * @return Canonical message.
     */
    fun logEntry(fields: LogFields): ByteString =
        Canonical()
            .label("cloak/v1/vault-log")
            .uuid(fields.vaultId.value)
            .u64(fields.seq)
            .digest32(fields.previousHash)
            .u8(fields.kind.protocolCode)
            .uuid(fields.subjectUserId?.value)
            .u8(fields.role?.protocolCode ?: 0)
            .u32(fields.keyVersion)
            .digest32(fields.subjectKeys)
            .u32(fields.subjectKeyVersion ?: 0)
            .digest32(fields.keyCommitment)
            .digest32(fields.checkpoint)
            .flag(fields.requestEnd)
            .uuid(fields.authorUserId.value)
            .u32(fields.authorKeyVersion)
            .uuid(fields.nodeId?.value)
            .uuid(fields.homeVaultId?.value)
            .str(fields.nodeKey)
            .str(fields.sections)
            .build()

    /**
     * Builds a section write's signed message (§8.2).
     *
     * @param fields Write fields.
     * @return Canonical message.
     */
    fun sectionWrite(fields: SectionWriteFields): ByteString =
        Canonical()
            .label("cloak/v1/section-write")
            .uuid(fields.vaultId.value)
            .uuid(fields.nodeId.value)
            .str(fields.nodeType.value)
            .uuid(fields.origin.homeVaultId.value)
            .uuid(fields.origin.ownerUserId.value)
            .str(fields.origin.nodeKey.value)
            .str(fields.sectionName.value)
            .u32(fields.vaultKeyVersion)
            .u64(fields.dataVersion)
            .flag(fields.deleted)
            .u64(fields.logSeq)
            .digest32(fields.logHeadHash)
            .digest32(fields.previousWriteHash)
            .uuid(fields.writerUserId.value)
            .u32(fields.writerKeyVersion)
            .digest32(fields.ciphertextHash)
            .build()
}
