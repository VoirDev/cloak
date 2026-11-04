package dev.voir.cloak.server

import dev.voir.cloak.server.identity.domain.DeleteIdentityCommand
import dev.voir.cloak.server.identity.domain.UpdateCredentialsCommand
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.protocol.LogFields
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.SectionWriteFields
import dev.voir.cloak.server.protocol.sha256
import dev.voir.cloak.server.section.domain.BatchWriteItem
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.section.domain.SectionWrite
import dev.voir.cloak.server.section.domain.SectionWriteInput
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.testing.TestPostgres
import dev.voir.cloak.server.vault.domain.AddMemberCommand
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.CreateVaultCommand
import dev.voir.cloak.server.vault.domain.LeaveVaultCommand
import dev.voir.cloak.server.vault.domain.LeftOutWrite
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.MemberEnvelope
import dev.voir.cloak.server.vault.domain.RecordKeyReplacementCommand
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.RotateVaultCommand
import dev.voir.cloak.server.vault.domain.SetMemberRoleCommand
import dev.voir.cloak.server.vault.domain.Vault
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import javax.sql.DataSource
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.Uuid

/**
 * A Cloak server on a fresh `cloak` schema, with a controllable clock and helpers that act like a
 * client: they read the vault's head and sections from the server, then sign.
 */
internal class CloakFixture(settings: CloakSettings = CloakSettings.defaults()) {
    /** Controllable time. */
    val clock = TestClock(Instant.parse("2026-11-06T10:00:00Z"))

    /** The fresh database. */
    val dataSource: DataSource = TestPostgres.freshDataSource()

    /** Server under test. */
    val server = CloakServer(dataSource, clock, settings)

    /** Runs one SQL statement on the database directly, as an operator would, to set up a state. */
    fun sql(statement: String) {
        dataSource.connection.use { connection -> connection.createStatement().use { it.execute(statement) } }
    }

    /** Reads one number from the database directly, such as a row count. */
    fun number(query: String): Long =
        dataSource.connection.use { connection ->
            connection.createStatement().use { it.executeQuery(query).apply { next() }.getLong(1) }
        }

    /** Registers a new user with a fresh identity. */
    fun user(): TestClient = TestClient().also { server.identity.register(it.hostUserId, it.registration()) }

    /** The vault as [reader] sees it. */
    fun vault(reader: TestClient, vaultId: VaultId): Vault = server.vaults.get(reader.id, vaultId)

    /**
     * Signs one entry as [author], continuing the head [reader] sees (the author by default).
     *
     * @return The entry.
     */
    fun entry(
        author: TestClient,
        vaultId: VaultId,
        kind: LogEntryKind,
        subject: TestClient? = null,
        role: Role? = null,
        keyVersion: Int? = null,
        keyCommitment: ByteString? = null,
        checkpoint: ByteString? = null,
        seq: Long? = null,
        previousHash: ByteString? = null,
        requestEnd: Boolean = true,
        subjectKeyVersion: Int? = null,
        subjectKeys: ByteString? = null,
        nodeId: NodeId? = null,
        homeVaultId: VaultId? = null,
        nodeKey: String? = null,
        sections: String? = null,
    ): LogEntryInput {
        val head = runCatching { vault(author, vaultId) }.getOrNull()
        val fields = LogFields(
            vaultId = vaultId,
            seq = seq ?: ((head?.logSeq ?: 0) + 1),
            previousHash = previousHash ?: head?.logHeadHash,
            kind = kind,
            subjectUserId = subject?.id,
            role = role,
            keyVersion = keyVersion ?: head?.keyVersion ?: 1,
            subjectKeys = subjectKeys ?: subject?.let { Messages.keysDigest(it.keys) },
            subjectKeyVersion = subjectKeyVersion ?: subject?.keys?.keyVersion,
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
        return fields.toInput(author.signEntry(fields))
    }

    /** Node origins created or known by this fixture, by node id. */
    private val origins = mutableMapOf<NodeId, NodeOrigin>()

    /**
     * Creates a node owned by [owner] in [vaultId], its home, with a signed `node_created`
     * (`PROTOCOL.md` §7.7), and remembers its origin for later writes.
     *
     * @return The node's id.
     */
    fun node(owner: TestClient, vaultId: VaultId, key: String = Uuid.random().toString()): NodeId {
        val origin = NodeOrigin(owner.id, vaultId, NodeKey(key))
        val log = entry(owner, vaultId, LogEntryKind.NODE_CREATED, nodeId = origin.nodeId, nodeKey = key)
        server.vaults.appendNodeEntry(owner.id, vaultId, log)
        origins[origin.nodeId] = origin
        return origin.nodeId
    }

    /**
     * Shares names of a node into another vault as its owner, with a signed `node_shared`.
     *
     * @return The vault after the entry.
     */
    fun share(owner: TestClient, vaultId: VaultId, nodeId: NodeId, sections: String = "*"): Vault {
        val origin = checkNotNull(origins[nodeId]) { "Unknown node" }
        val log = entry(
            owner, vaultId, LogEntryKind.NODE_SHARED,
            nodeId = nodeId, homeVaultId = origin.homeVaultId, nodeKey = origin.nodeKey.value, sections = sections,
        )
        return server.vaults.appendNodeEntry(owner.id, vaultId, log)
    }

    /** The origin of a node this fixture created. */
    fun originOf(nodeId: NodeId): NodeOrigin = checkNotNull(origins[nodeId]) { "Unknown node $nodeId" }

    /** Remembers the origin of a node made outside [node], such as by hand-signed entries. */
    fun know(origin: NodeOrigin): NodeId = origin.nodeId.also { origins[it] = origin }

    /** Creates a vault owned by [owner]. */
    fun createVault(owner: TestClient, id: VaultId = VaultId(Uuid.random())): VaultId {
        val log = entry(owner, id, LogEntryKind.VAULT_CREATED, subject = owner, role = Role.OWNER, keyVersion = 1, keyCommitment = TestBlobs.random(32), seq = 1)
        server.vaults.create(owner.id, CreateVaultCommand(id, TestBlobs.envelope(), log))
        return id
    }

    /** Adds [user] to a vault as [role], signed by [admin]. */
    fun addMember(admin: TestClient, vaultId: VaultId, user: TestClient, role: Role): Vault {
        val log = entry(admin, vaultId, LogEntryKind.MEMBER_ADDED, subject = user, role = role)
        val keyVersion = vault(admin, vaultId).keyVersion
        return server.members.add(admin.id, vaultId, AddMemberCommand(user.id, role, keyVersion, user.keys.keyVersion, TestBlobs.envelope(), log))
    }

    /** Changes [user]'s role, with a checkpoint when [withCheckpoint]. */
    fun setRole(admin: TestClient, vaultId: VaultId, user: TestClient, role: Role, withCheckpoint: Boolean = false): Vault {
        val log = entry(
            admin,
            vaultId,
            LogEntryKind.MEMBER_ROLE_SET,
            subject = user,
            role = role,
            checkpoint = if (withCheckpoint) checkpoint(admin, vaultId) else null,
            subjectKeyVersion = committedVersion(admin, vaultId, user),
            subjectKeys = committedDigest(admin, vaultId, user),
        )
        return server.members.setRole(admin.id, vaultId, user.id, SetMemberRoleCommand(role, log))
    }

    /** [user] leaves, with a checkpoint when [withCheckpoint]. */
    fun leave(user: TestClient, vaultId: VaultId, withCheckpoint: Boolean) {
        val log = entry(user, vaultId, LogEntryKind.MEMBER_REMOVED, subject = user, checkpoint = if (withCheckpoint) checkpoint(user, vaultId) else null)
        server.members.leave(user.id, vaultId, LeaveVaultCommand(log))
    }

    /**
     * Rotates the key, removing [removed], and seals the new key to [recipients].
     *
     * @return The vault afterwards.
     */
    fun rotate(
        admin: TestClient,
        vaultId: VaultId,
        removed: List<TestClient> = emptyList(),
        recipients: List<Pair<TestClient, Int>>,
        leftOut: List<LeftOutWrite> = emptyList(),
        checkpoint: ByteString? = null,
    ): Vault = server.members.rotate(admin.id, vaultId, rotation(admin, vaultId, removed, recipients, leftOut, checkpoint))

    /**
     * Builds a signed rotation that removes [removed] and seals the new key to [recipients],
     * against the vault's current state, without sending it.
     *
     * @return The rotation.
     */
    fun rotation(
        admin: TestClient,
        vaultId: VaultId,
        removed: List<TestClient> = emptyList(),
        recipients: List<Pair<TestClient, Int>>,
        leftOut: List<LeftOutWrite> = emptyList(),
        checkpoint: ByteString? = null,
    ): RotateVaultCommand {
        val head = vault(admin, vaultId)
        val entries = mutableListOf<LogEntryInput>()
        var seq = head.logSeq
        var hash: ByteString? = head.logHeadHash
        val next = head.keyVersion + 1
        removed.forEach { user ->
            entries += entry(
                admin, vaultId, LogEntryKind.MEMBER_REMOVED, subject = user, keyVersion = head.keyVersion,
                seq = seq + 1, previousHash = hash, requestEnd = false,
                subjectKeyVersion = committedVersion(admin, vaultId, user), subjectKeys = committedDigest(admin, vaultId, user),
            )
            seq += 1
            hash = sha256(Messages.logEntry(entries.last().toFields(vaultId, admin, hash)))
        }
        entries += entry(
            admin, vaultId, LogEntryKind.KEY_ROTATED, keyVersion = next, keyCommitment = TestBlobs.random(32),
            checkpoint = checkpoint ?: checkpoint(admin, vaultId, leftOut), seq = seq + 1, previousHash = hash,
        )
        val envelopes = recipients.map { (user, version) -> MemberEnvelope(user.id, version, TestBlobs.envelope()) }
        return RotateVaultCommand(next, TestBlobs.wrappedKey(), envelopes, entries, leftOut)
    }

    /**
     * Signs a credentials change for [user] from [expected] (`PROTOCOL.md` §5.4): the statement
     * names version `expected + 1` and is signed by the user's current keys.
     */
    fun credentialsChange(
        user: TestClient,
        expected: Int,
        kdf: KdfParams = KdfParams(TestBlobs.random(16), 131_072, 4),
        bundle: ByteString = TestBlobs.blob(41 + 129),
    ): UpdateCredentialsCommand {
        val statement = Messages.credentials(user.id, user.keys.keyVersion, expected + 1, bundle, kdf)
        return UpdateCredentialsCommand(expected, kdf, bundle, user.sign(statement))
    }

    /**
     * Signs [user]'s identity deletion (`PROTOCOL.md` §5.7) at [credentialsVersion], valid until
     * [notAfter] (five minutes from the fixture's clock by default).
     */
    fun deletion(
        user: TestClient,
        credentialsVersion: Int = 1,
        notAfter: Long = clock.now.epochSeconds + 300,
    ): DeleteIdentityCommand {
        val statement = Messages.identityDeletion(user.id, user.keys.keyVersion, credentialsVersion, notAfter)
        return DeleteIdentityCommand(credentialsVersion, notAfter, user.sign(statement))
    }

    /** Deletes [user]'s identity with a fresh signed statement at their current credentials version. */
    fun deleteIdentity(user: TestClient) {
        val version = server.identity.get(user.id).credentialsVersion
        server.identity.delete(user.id, deletion(user, version))
    }

    /** Replaces [user]'s identity keys. */
    fun replaceKeys(user: TestClient) {
        server.identity.replaceKeys(user.id, user.replacement())
        user.acceptReplacement()
    }

    /** Records [user]'s new keys in a vault, with a checkpoint when [withCheckpoint], and an envelope when [withEnvelope]. */
    fun recordReplacement(
        user: TestClient,
        vaultId: VaultId,
        withCheckpoint: Boolean,
        leftOut: List<LeftOutWrite> = emptyList(),
        withEnvelope: Boolean = true,
    ): Vault {
        val log = entry(
            user, vaultId, LogEntryKind.MEMBER_KEYS_REPLACED, subject = user,
            checkpoint = if (withCheckpoint) checkpoint(user, vaultId, leftOut) else null,
        )
        return server.members.recordKeyReplacement(user.id, vaultId, RecordKeyReplacementCommand(log, if (withEnvelope) TestBlobs.envelope() else null, leftOut))
    }

    /**
     * Writes a section as [writer], reading the head and the latest write first.
     *
     * @return The stored write.
     */
    fun write(
        writer: TestClient,
        vaultId: VaultId,
        nodeId: NodeId,
        name: String,
        deleted: Boolean = false,
        nodeType: String = "compute.vps",
    ): SectionWrite = server.sections.write(writer.id, SectionRef(vaultId, nodeId, SectionName(name)), writeInput(writer, vaultId, nodeId, name, deleted, nodeType))

    /**
     * Creates [count] new sections named [name] on fresh nodes, as [writer], in batches of 100
     * that each cite the current head.
     *
     * @return The new nodes, in write order.
     */
    fun writeMany(writer: TestClient, vaultId: VaultId, count: Int, name: String = "general"): List<NodeId> =
        List(count) { node(writer, vaultId) }.chunked(100).flatMap { chunk ->
            val head = vault(writer, vaultId)
            val items = chunk.map { nodeId ->
                val ciphertext = TestBlobs.ciphertext()
                val origin = originOf(nodeId)
                val fields = SectionWriteFields(
                    vaultId = vaultId,
                    nodeId = nodeId,
                    nodeType = NodeType("compute.vps"),
                    origin = origin,
                    sectionName = SectionName(name),
                    vaultKeyVersion = head.keyVersion,
                    dataVersion = 1,
                    deleted = false,
                    logSeq = head.logSeq,
                    logHeadHash = head.logHeadHash,
                    previousWriteHash = null,
                    writerUserId = writer.id,
                    writerKeyVersion = writer.keys.keyVersion,
                    ciphertextHash = sha256(ciphertext),
                )
                BatchWriteItem(
                    SectionRef(vaultId, nodeId, SectionName(name)),
                    SectionWriteInput(
                        fields.nodeType, fields.vaultKeyVersion, fields.dataVersion, fields.deleted, fields.logSeq,
                        fields.logHeadHash, null, fields.writerKeyVersion, ciphertext, writer.signWrite(fields),
                        origin.homeVaultId, origin.ownerUserId, origin.nodeKey.value,
                    ),
                )
            }
            server.sections.batchWrite(writer.id, items)
            chunk
        }

    /** Builds a signed write of a section against the current state. */
    fun writeInput(
        writer: TestClient,
        vaultId: VaultId,
        nodeId: NodeId,
        name: String,
        deleted: Boolean = false,
        nodeType: String = "compute.vps",
    ): SectionWriteInput {
        val head = vault(writer, vaultId)
        val ref = SectionRef(vaultId, nodeId, SectionName(name))
        val latest = runCatching { server.sections.get(writer.id, ref) }.getOrNull()
        val ciphertext = if (deleted) null else TestBlobs.ciphertext()
        val origin = originOf(nodeId)
        val fields = SectionWriteFields(
            vaultId = vaultId,
            nodeId = nodeId,
            nodeType = NodeType(nodeType),
            origin = origin,
            sectionName = SectionName(name),
            vaultKeyVersion = head.keyVersion,
            dataVersion = (latest?.input?.dataVersion ?: 0) + 1,
            deleted = deleted,
            logSeq = head.logSeq,
            logHeadHash = head.logHeadHash,
            previousWriteHash = latest?.writeHash,
            writerUserId = writer.id,
            writerKeyVersion = writer.keys.keyVersion,
            ciphertextHash = ciphertext?.let(::sha256),
        )
        return SectionWriteInput(
            fields.nodeType, fields.vaultKeyVersion, fields.dataVersion, fields.deleted, fields.logSeq,
            fields.logHeadHash, fields.previousWriteHash, fields.writerKeyVersion, ciphertext, writer.signWrite(fields),
            origin.homeVaultId, origin.ownerUserId, origin.nodeKey.value,
        )
    }

    /** The checkpoint over the vault's latest writes as [reader] reads them, minus [leftOut]. */
    fun checkpoint(reader: TestClient, vaultId: VaultId, leftOut: List<LeftOutWrite> = emptyList()): ByteString {
        val excluded = leftOut.map { it.nodeId to it.sectionName }.toSet()
        return Merkle.root(leaves(reader, vaultId).filterNot { (it.nodeId to it.sectionName) in excluded })
    }

    /**
     * The latest write of every live section of a vault as sorted leaves, read through the change
     * feed: a deletion is never a leaf (`PROTOCOL.md` §7.5).
     */
    fun leaves(reader: TestClient, vaultId: VaultId): List<CheckpointLeaf> {
        val writes = mutableListOf<SectionWrite>()
        var after: Long? = null
        do {
            val page = server.sections.list(reader.id, vaultId, after, limit = 100)
            writes += page.items
            after = page.throughChangeSeq
        } while (page.throughChangeSeq < page.lastChangeSeq)
        return writes.filterNot { it.input.deleted }
            .map { CheckpointLeaf(it.section.nodeId, it.section.sectionName, it.input.dataVersion, it.writeHash) }
            .sortedWith(Merkle.sectionOrder)
    }

    /** [user]'s committed key version in a vault, read from the log. */
    private fun committedVersion(reader: TestClient, vaultId: VaultId, user: TestClient): Int =
        committed(reader, vaultId, user).first

    /** [user]'s committed keys digest in a vault, read from the log. */
    private fun committedDigest(reader: TestClient, vaultId: VaultId, user: TestClient): ByteString =
        committed(reader, vaultId, user).second

    /** The last version and digest the log committed for [user]. */
    private fun committed(reader: TestClient, vaultId: VaultId, user: TestClient): Pair<Int, ByteString> {
        val entry = server.vaults.log(reader.id, vaultId, limit = 100).items
            .map { it.input }
            .last { it.subjectUserId == user.id && it.subjectKeys != null && it.kind != LogEntryKind.MEMBER_REMOVED }
        return checkNotNull(entry.subjectKeyVersion) to checkNotNull(entry.subjectKeys)
    }

    /** A clock tests move by hand. */
    class TestClock(var now: Instant) : Clock {
        override fun now(): Instant = now

        /** Moves time forward. */
        fun advance(by: Duration) {
            now += by
        }
    }

    /** Conversions between the request and protocol shapes of an entry. */
    companion object {
        /** The request shape of signed fields. */
        fun LogFields.toInput(signature: ByteString): LogEntryInput =
            LogEntryInput(
                seq, kind, subjectUserId, role, keyVersion, subjectKeys, subjectKeyVersion, keyCommitment, checkpoint, requestEnd,
                authorKeyVersion, signature, nodeId, homeVaultId, nodeKey.ifEmpty { null }, sections.ifEmpty { null },
            )

        /** The protocol fields of a request entry that follows the entry hashed [previousHash]. */
        fun LogEntryInput.toFields(vaultId: VaultId, author: TestClient, previousHash: ByteString?): LogFields =
            LogFields(
                vaultId, seq, previousHash, kind, subjectUserId, role, keyVersion, subjectKeys, subjectKeyVersion, keyCommitment, checkpoint,
                requestEnd, author.id, authorKeyVersion, nodeId, homeVaultId, nodeKey.orEmpty(), sections.orEmpty(),
            )
    }
}
