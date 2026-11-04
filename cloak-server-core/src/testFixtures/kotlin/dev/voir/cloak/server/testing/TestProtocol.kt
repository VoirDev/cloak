package dev.voir.cloak.server.testing

import dev.voir.cloak.server.identity.domain.DeleteIdentityCommand
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UpdateCredentialsCommand
import dev.voir.cloak.server.protocol.LogFields
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.SectionWriteFields
import dev.voir.cloak.server.protocol.sha256
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.section.domain.SectionWriteInput
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString

/**
 * The protocol's messages for tests outside the core, such as the HTTP tests of an adapter: they
 * sign entries and writes like a real client without reaching the core's internals.
 */
public object TestProtocol {
    /**
     * `keysDigest` of a key version.
     *
     * @param keys The key version.
     * @return The digest the log commits.
     */
    public fun keysDigest(keys: PublicKeys): ByteString = Messages.keysDigest(keys)

    /**
     * The checkpoint over leaves in any order.
     *
     * @param leaves Latest writes.
     * @return The Merkle root.
     */
    public fun checkpoint(leaves: List<CheckpointLeaf>): ByteString = Merkle.root(leaves.sortedWith(Merkle.sectionOrder))

    /**
     * Hashes bytes, as a write's `ciphertextHash` does.
     *
     * @param bytes Bytes to hash.
     * @return SHA-256 of [bytes].
     */
    public fun sha256(bytes: ByteString): ByteString = dev.voir.cloak.server.protocol.sha256(bytes)

    /**
     * Signs one log entry as [author].
     *
     * @param author Signer.
     * @param vaultId Vault.
     * @param seq Position.
     * @param previousHash Hash of the previous entry; `null` for `seq` 1.
     * @param kind Kind.
     * @param subject Subject's key version, when the kind has a subject.
     * @param role Role set.
     * @param keyVersion Vault key version after the entry.
     * @param keyCommitment Commitment of a new key version.
     * @param checkpoint Checkpoint.
     * @param requestEnd Whether the entry ends its request.
     * @param nodeId Node a node entry names.
     * @param homeVaultId Home vault of the node `node_shared` shares.
     * @param nodeKey Key of the node `node_created` creates or `node_shared` shares.
     * @param sections Names a node entry covers.
     * @return The entry and its `entryHash`.
     */
    public fun logEntry(
        author: TestClient,
        vaultId: VaultId,
        seq: Long,
        previousHash: ByteString?,
        kind: LogEntryKind,
        subject: PublicKeys? = null,
        role: Role? = null,
        keyVersion: Int,
        keyCommitment: ByteString? = null,
        checkpoint: ByteString? = null,
        requestEnd: Boolean = true,
        nodeId: NodeId? = null,
        homeVaultId: VaultId? = null,
        nodeKey: String? = null,
        sections: String? = null,
    ): Pair<LogEntryInput, ByteString> {
        val fields = LogFields(
            vaultId = vaultId,
            seq = seq,
            previousHash = previousHash,
            kind = kind,
            subjectUserId = subject?.userId,
            role = role,
            keyVersion = keyVersion,
            subjectKeys = subject?.let(Messages::keysDigest),
            subjectKeyVersion = subject?.keyVersion,
            keyCommitment = keyCommitment,
            checkpoint = checkpoint,
            requestEnd = requestEnd,
            authorUserId = author.id,
            authorKeyVersion = author.keys.keyVersion,
            nodeId = nodeId,
            homeVaultId = homeVaultId,
            nodeKey = nodeKey.orEmpty(),
            sections = sections.orEmpty(),
        )
        val message = Messages.logEntry(fields)
        val input = LogEntryInput(
            seq, kind, fields.subjectUserId, role, keyVersion, fields.subjectKeys, fields.subjectKeyVersion,
            keyCommitment, checkpoint, requestEnd, fields.authorKeyVersion, author.sign(message),
            nodeId, homeVaultId, nodeKey, sections,
        )
        return input to sha256(message)
    }

    /**
     * Signs a section write as [writer].
     *
     * @param writer Signer.
     * @param section The section.
     * @param nodeType App-defined type.
     * @param vaultKeyVersion Vault key version.
     * @param dataVersion Version the write creates.
     * @param logSeq Cited head.
     * @param logHeadHash Hash of the cited head.
     * @param previousWriteHash Hash of the latest write; `null` for the first.
     * @param ciphertext Content; `null` for a deletion.
     * @param origin The node's owner, home and key; its id must be the section's node.
     * @return The signed write and its `writeHash`.
     */
    public fun sectionWrite(
        writer: TestClient,
        section: SectionRef,
        nodeType: NodeType,
        vaultKeyVersion: Int,
        dataVersion: Long,
        logSeq: Long,
        logHeadHash: ByteString,
        previousWriteHash: ByteString?,
        ciphertext: ByteString?,
        origin: NodeOrigin,
    ): Pair<SectionWriteInput, ByteString> {
        val fields = SectionWriteFields(
            section.vaultId, section.nodeId, nodeType, origin, section.sectionName, vaultKeyVersion, dataVersion,
            ciphertext == null, logSeq, logHeadHash, previousWriteHash, writer.id, writer.keys.keyVersion, ciphertext?.let(::sha256),
        )
        val message = Messages.sectionWrite(fields)
        val input = SectionWriteInput(
            nodeType, vaultKeyVersion, dataVersion, ciphertext == null, logSeq, logHeadHash, previousWriteHash,
            writer.keys.keyVersion, ciphertext, writer.sign(message),
            origin.homeVaultId, origin.ownerUserId, origin.nodeKey.value,
        )
        return input to sha256(message)
    }

    /**
     * Signs a credentials change from [expected] (`PROTOCOL.md` §5.4): the statement names
     * version `expected + 1` and is signed by [user]'s current keys.
     *
     * @return The command.
     */
    public fun credentialsChange(user: TestClient, expected: Int, kdf: KdfParams, privateKeyBundle: ByteString): UpdateCredentialsCommand {
        val statement = Messages.credentials(user.id, user.keys.keyVersion, expected + 1, privateKeyBundle, kdf)
        return UpdateCredentialsCommand(expected, kdf, privateKeyBundle, user.sign(statement))
    }

    /**
     * Signs [user]'s identity deletion (`PROTOCOL.md` §5.7) at [credentialsVersion], valid until
     * [notAfter] in Unix seconds.
     *
     * @return The command.
     */
    public fun identityDeletion(user: TestClient, credentialsVersion: Int, notAfter: Long): DeleteIdentityCommand {
        val statement = Messages.identityDeletion(user.id, user.keys.keyVersion, credentialsVersion, notAfter)
        return DeleteIdentityCommand(credentialsVersion, notAfter, user.sign(statement))
    }
}
