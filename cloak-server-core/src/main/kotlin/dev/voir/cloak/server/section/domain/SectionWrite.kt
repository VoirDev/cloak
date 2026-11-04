package dev.voir.cloak.server.section.domain

import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * Identifies a section: its vault, node and name. The same node and name in two vaults are two
 * sections.
 *
 * @property vaultId Vault the section lives in.
 * @property nodeId Node of the section.
 * @property sectionName Section name.
 */
public data class SectionRef(
    /** Vault the section lives in. */
    public val vaultId: VaultId,
    /** Node of the section. */
    public val nodeId: NodeId,
    /** Section name. */
    public val sectionName: SectionName,
)

/**
 * One signed section write as a client sends it (`PROTOCOL.md` §8.2); the writer is the caller.
 *
 * @property nodeType App-defined node type.
 * @property vaultKeyVersion Vault key version that encrypts the content.
 * @property dataVersion Version this write creates.
 * @property deleted Whether the write deletes the section.
 * @property logSeq Log head the writer verified.
 * @property logHeadHash `entryHash` of that head.
 * @property previousWriteHash `writeHash` of the section's latest write; `null` for the first.
 * @property writerKeyVersion The writer's identity key version that signs.
 * @property ciphertext Section ciphertext; `null` for a deletion.
 * @property signature The writer's signature.
 * @property homeVaultId The node's home vault, signed with the write (`PROTOCOL.md` §8.1).
 * @property ownerUserId The node's owner, signed with the write.
 * @property nodeKey The node's key, signed with the write; 1 to 255 bytes of UTF-8.
 */
public data class SectionWriteInput(
    /** App-defined node type. */
    public val nodeType: NodeType,
    /** Vault key version of the content. */
    public val vaultKeyVersion: Int,
    /** Version this write creates. */
    public val dataVersion: Long,
    /** Whether the write deletes the section. */
    public val deleted: Boolean,
    /** Log head the writer verified. */
    public val logSeq: Long,
    /** Hash of that head. */
    public val logHeadHash: ByteString,
    /** Hash of the section's latest write. */
    public val previousWriteHash: ByteString?,
    /** The writer's key version. */
    public val writerKeyVersion: Int,
    /** Section ciphertext. */
    public val ciphertext: ByteString?,
    /** The writer's signature. */
    public val signature: ByteString,
    /** The node's home vault. */
    public val homeVaultId: VaultId,
    /** The node's owner. */
    public val ownerUserId: UserId,
    /** The node's key. */
    public val nodeKey: String,
)

/**
 * One item of a batch write.
 *
 * @property section The section to write.
 * @property input The signed write.
 */
public data class BatchWriteItem(
    /** The section to write. */
    public val section: SectionRef,
    /** The signed write. */
    public val input: SectionWriteInput,
)

/**
 * A stored section write: the latest of its section.
 *
 * @property section The section.
 * @property input The signed fields and signature as the writer sent them.
 * @property writerUserId Writer.
 * @property ciphertextHash SHA-256 of the ciphertext, which the write signs; `null` for a deletion.
 * @property writeHash SHA-256 of the signed message.
 * @property changeSeq Change number of the write within its vault.
 * @property writtenAt Instant the write was stored.
 */
public data class SectionWrite(
    /** The section. */
    public val section: SectionRef,
    /** The signed fields and signature. */
    public val input: SectionWriteInput,
    /** Writer. */
    public val writerUserId: UserId,
    /** SHA-256 of the ciphertext. */
    public val ciphertextHash: ByteString?,
    /** SHA-256 of the signed message. */
    public val writeHash: ByteString,
    /** Change number within the vault. */
    public val changeSeq: Long,
    /** Instant the write was stored. */
    public val writtenAt: Instant,
) {
    /** The write without its ciphertext. */
    public val header: SectionHeader
        get() = SectionHeader(
            section = section,
            nodeType = input.nodeType,
            homeVaultId = input.homeVaultId,
            ownerUserId = input.ownerUserId,
            nodeKey = input.nodeKey,
            vaultKeyVersion = input.vaultKeyVersion,
            dataVersion = input.dataVersion,
            deleted = input.deleted,
            logSeq = input.logSeq,
            logHeadHash = input.logHeadHash,
            previousWriteHash = input.previousWriteHash,
            writerUserId = writerUserId,
            writerKeyVersion = input.writerKeyVersion,
            ciphertextHash = ciphertextHash,
            signature = input.signature,
            writeHash = writeHash,
            changeSeq = changeSeq,
            writtenAt = writtenAt,
        )
}

/**
 * A stored write without its ciphertext (`PROTOCOL.md` §8.2): enough to check its signature and
 * standing, since the write signs only the ciphertext's digest.
 *
 * @property section The section.
 * @property nodeType App-defined node type.
 * @property homeVaultId The node's home vault, as the writer signed it.
 * @property ownerUserId The node's owner, as the writer signed it.
 * @property nodeKey The node's key, as the writer signed it.
 * @property vaultKeyVersion Vault key version that encrypts the content.
 * @property dataVersion Version of the write.
 * @property deleted Whether the write deletes the section.
 * @property logSeq Log head the writer cited.
 * @property logHeadHash `entryHash` of that head.
 * @property previousWriteHash `writeHash` of the previous write; `null` for the first.
 * @property writerUserId Writer.
 * @property writerKeyVersion The writer's identity key version that signed.
 * @property ciphertextHash SHA-256 of the ciphertext; `null` for a deletion.
 * @property signature The writer's signature.
 * @property writeHash SHA-256 of the signed message.
 * @property changeSeq Change number of the write within its vault.
 * @property writtenAt Instant the write was stored.
 */
public data class SectionHeader(
    /** The section. */
    public val section: SectionRef,
    /** App-defined node type. */
    public val nodeType: NodeType,
    /** The node's home vault. */
    public val homeVaultId: VaultId,
    /** The node's owner. */
    public val ownerUserId: UserId,
    /** The node's key. */
    public val nodeKey: String,
    /** Vault key version of the content. */
    public val vaultKeyVersion: Int,
    /** Version of the write. */
    public val dataVersion: Long,
    /** Whether the write deletes the section. */
    public val deleted: Boolean,
    /** Log head the writer cited. */
    public val logSeq: Long,
    /** Hash of that head. */
    public val logHeadHash: ByteString,
    /** Hash of the previous write. */
    public val previousWriteHash: ByteString?,
    /** Writer. */
    public val writerUserId: UserId,
    /** The writer's key version. */
    public val writerKeyVersion: Int,
    /** SHA-256 of the ciphertext. */
    public val ciphertextHash: ByteString?,
    /** The writer's signature. */
    public val signature: ByteString,
    /** SHA-256 of the signed message. */
    public val writeHash: ByteString,
    /** Change number within the vault. */
    public val changeSeq: Long,
    /** Instant the write was stored. */
    public val writtenAt: Instant,
)

/**
 * A section the host removed with its node (`PROTOCOL.md` §15), at the change number the removal took.
 *
 * @property nodeId Node of the section.
 * @property sectionName Name of the section.
 * @property changeSeq Change number of the removal in its vault.
 */
public data class SectionRemoval(
    /** Node of the section. */
    public val nodeId: NodeId,
    /** Name of the section. */
    public val sectionName: SectionName,
    /** Change number of the removal. */
    public val changeSeq: Long,
)

/**
 * One page of a vault's sections in change order: every change after the asked change number up to
 * [throughChangeSeq], writes and removals both.
 *
 * @property items Latest writes, by change number.
 * @property removed Sections the host removed in the same range, by change number.
 * @property throughChangeSeq Last change number the page covers; the next page starts after it.
 * @property lastChangeSeq The vault's latest change number; read on while [throughChangeSeq] is before it.
 */
public data class SectionPage(
    /** Latest writes, by change number. */
    public val items: List<SectionWrite>,
    /** Removed sections, by change number. */
    public val removed: List<SectionRemoval>,
    /** Last change number the page covers. */
    public val throughChangeSeq: Long,
    /** The vault's latest change number. */
    public val lastChangeSeq: Long,
)

/**
 * One page of a vault's section headers in change order, like [SectionPage] without ciphertext.
 *
 * @property items Latest writes without their ciphertext, by change number.
 * @property removed Sections the host removed in the same range, by change number.
 * @property throughChangeSeq Last change number the page covers; the next page starts after it.
 * @property lastChangeSeq The vault's latest change number; read on while [throughChangeSeq] is before it.
 */
public data class SectionHeaderPage(
    /** Latest writes without ciphertext, by change number. */
    public val items: List<SectionHeader>,
    /** Removed sections, by change number. */
    public val removed: List<SectionRemoval>,
    /** Last change number the page covers. */
    public val throughChangeSeq: Long,
    /** The vault's latest change number. */
    public val lastChangeSeq: Long,
)

/**
 * The sections of a node the caller can read, across vaults.
 *
 * @property nodeId The node.
 * @property sections Latest writes of its readable sections.
 */
public data class NodeSections(
    /** The node. */
    public val nodeId: NodeId,
    /** Latest writes of its readable sections. */
    public val sections: List<SectionWrite>,
)

/**
 * Result of reading several nodes.
 *
 * @property items Nodes with at least one readable section.
 * @property missingNodeIds Requested nodes without one.
 */
public data class NodeSectionsBatch(
    /** Nodes with a readable section. */
    public val items: List<NodeSections>,
    /** Requested nodes without one. */
    public val missingNodeIds: List<NodeId>,
)
