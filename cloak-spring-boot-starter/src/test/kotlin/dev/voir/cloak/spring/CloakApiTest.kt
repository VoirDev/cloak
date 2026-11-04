package dev.voir.cloak.spring

import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.testing.TestProtocol
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.spring.CloakApi.Companion.b64
import dev.voir.cloak.spring.CloakApi.Companion.bytes
import dev.voir.cloak.spring.testhost.CloakTestApplication
import kotlinx.io.bytestring.ByteString
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.HttpMethod.GET
import org.springframework.http.HttpMethod.PATCH
import org.springframework.http.HttpMethod.POST
import org.springframework.http.HttpMethod.PUT
import org.springframework.test.web.servlet.MockMvc
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping
import tools.jackson.databind.json.JsonMapper
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/** The whole API over HTTP, every response checked against the OpenAPI contract. */
@SpringBootTest(classes = [CloakTestApplication::class])
@AutoConfigureMockMvc
class CloakApiTest {
    @Autowired
    private lateinit var mvc: MockMvc

    @Autowired
    private lateinit var mapper: JsonMapper

    private lateinit var api: CloakApi

    @BeforeTest
    fun setUp() {
        api = CloakApi(mvc, mapper)
    }

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private lateinit var mappings: RequestMappingHandlerMapping

    @Test
    fun `the starter serves every operation of the contract and nothing else`() {
        val served = mappings.handlerMethods.keys.flatMap { info ->
            val paths = info.pathPatternsCondition?.patternValues.orEmpty().filter { it.startsWith("/cloak/v1/") }
            paths.flatMap { path -> info.methodsCondition.methods.map { it.name to OpenApiContract.normalize(path.removePrefix("/cloak/v1")) } }
        }.toSet()

        assertEquals(OpenApiContract.operationKeys, served)
    }

    @Test
    fun `meta needs no session and other endpoints do`() {
        val meta = api.call(GET, "/meta")
        val problem = api.call(GET, "/identity")

        assertEquals(1000, meta["limits"]["maxMembersPerVault"].asInt())
        assertEquals(1000, meta["limits"]["maxIndexPageSize"].asInt())
        assertEquals(100_000, meta["limits"]["maxSectionsPerVault"].asInt())
        assertEquals(401, problem.status)
        assertEquals("unauthenticated", problem.code)
    }

    @Test
    fun `identity is registered once, read back, and its keys replaced`() {
        val alice = TestClient()

        assertEquals("identity_required", api.call(GET, "/identity", alice).code)
        assertEquals(201, api.call(POST, "/identity", alice, CloakApi.registration(alice)).status)
        assertEquals("already_exists", api.call(POST, "/identity", alice, CloakApi.registration(alice)).code)
        assertEquals(b64(alice.keys.signingPublicKey), api.call(GET, "/identity", alice)["keys"]["signingPublicKey"].asString())
        // The host's id travels with the identity and the keys; the user id derives from it.
        assertEquals(alice.hostUserId.value, api.call(GET, "/identity", alice)["hostUserId"].asString())
        assertEquals(alice.id.value.toString(), api.call(GET, "/identity", alice)["keys"]["userId"].asString())

        val replaced = api.call(PUT, "/identity/keys", alice, CloakApi.replacement(alice))
        alice.acceptReplacement()
        val keys = api.call(GET, "/users/${alice.id.value}/keys", alice)
        val batch = api.call(POST, "/users/keys/batch-get", alice, mapOf("userIds" to listOf(alice.id.value.toString(), Uuid.random().toString())))

        assertEquals(2, replaced["keys"]["keyVersion"].asInt())
        assertEquals(2, keys["versions"].size())
        assertEquals(alice.hostUserId.value, keys["hostUserId"].asString())
        assertEquals(alice.hostUserId.value, batch["items"][0]["hostUserId"].asString())
        assertEquals(1, batch["missingUserIds"].size())
    }

    @Test
    fun `a vault's members, roles, envelopes, departures and rotations`() {
        val alice = registered()
        val bob = registered()
        val carol = registered()
        val vault = createVault(alice)

        assertEquals(404, api.call(GET, "/vaults/${vault.value}", bob).status)
        assertEquals(201, addMember(alice, vault, bob, Role.EDITOR).status)
        addMember(alice, vault, carol, Role.VIEWER)
        assertEquals("role_required", addMember(bob, vault, registered(), Role.VIEWER).code)
        assertEquals(listOf(vault.value.toString()), api.call(GET, "/vaults?pending=true", bob)["items"].elements().map { it["id"].asString() })
        assertEquals(204, api.call(PUT, "/vaults/${vault.value}/acceptance", bob).status)
        assertEquals(listOf(vault.value.toString()), api.call(GET, "/vaults", bob)["items"].elements().map { it["id"].asString() })

        val node = node(alice, vault)
        write(bob, vault, node, "general")
        val (demotion, _) = entry(alice, vault, LogEntryKind.MEMBER_ROLE_SET, bob, Role.VIEWER, checkpoint = checkpoint(alice, vault))
        val demoted = api.call(PATCH, "/vaults/${vault.value}/members/${bob.id.value}", alice, mapOf("role" to "viewer", "log" to CloakApi.log(demotion)))
        assertEquals("viewer", api.call(GET, "/vaults/${vault.value}", bob)["role"].asString())
        assertEquals(200, demoted.status)

        val envelope = mapOf("keyVersion" to 1, "userKeyVersion" to 1, "keyEnvelope" to b64(TestBlobs.envelope()))
        assertEquals(204, api.call(PUT, "/vaults/${vault.value}/members/${carol.id.value}/envelope", carol, envelope).status)
        assertEquals("role_required", api.call(PUT, "/vaults/${vault.value}/members/${carol.id.value}/envelope", bob, envelope).code)

        val (leave, _) = entry(carol, vault, LogEntryKind.MEMBER_REMOVED, carol)
        assertEquals(204, api.call(POST, "/vaults/${vault.value}/departures", carol, mapOf("log" to CloakApi.log(leave))).status)

        val head = head(alice, vault)
        val (removal, removalHash) = TestProtocol.logEntry(
            alice, vault, head.first + 1, head.second, LogEntryKind.MEMBER_REMOVED, bob.keys, keyVersion = 1, requestEnd = false,
        )
        val (rotation, _) = TestProtocol.logEntry(
            alice, vault, head.first + 2, removalHash, LogEntryKind.KEY_ROTATED, keyVersion = 2,
            keyCommitment = TestBlobs.random(32), checkpoint = checkpoint(alice, vault),
        )
        val body = { envelopes: List<TestClient> ->
            mapOf(
                "keyVersion" to 2,
                "previousWrappedKey" to b64(TestBlobs.wrappedKey()),
                "envelopes" to envelopes.map { mapOf("userId" to it.id.value.toString(), "userKeyVersion" to 1, "keyEnvelope" to b64(TestBlobs.envelope())) },
                "log" to listOf(CloakApi.log(removal), CloakApi.log(rotation)),
            )
        }
        assertEquals("recipients_mismatch", api.call(POST, "/vaults/${vault.value}/rotations", alice, body(listOf(alice, bob))).code)
        val rotated = api.call(POST, "/vaults/${vault.value}/rotations", alice, body(listOf(alice)))

        assertEquals(2, rotated["keyVersion"].asInt())
        assertEquals(404, api.call(GET, "/vaults/${vault.value}", bob).status)
        assertEquals(2, api.call(GET, "/vaults/${vault.value}/keys", alice)["items"].size())
        // Two additions, the node, the demotion, the departure, the removal and the rotation.
        assertEquals(7, api.call(GET, "/vaults/${vault.value}/log?afterSeq=1", alice)["items"].size())
    }

    @Test
    fun `write pauses, batch reads and batch rotations over HTTP`() {
        val alice = registered()
        val bob = registered()
        val vault = createVault(alice)
        val other = createVault(alice)
        addMember(alice, vault, bob, Role.EDITOR)
        val node = node(alice, vault)

        val paused = api.call(POST, "/write-pauses", alice, mapOf("vaultIds" to listOf(vault.value.toString())))
        assertEquals(200, paused.status)
        assertTrue(paused["expiresAt"].asString().isNotEmpty())
        val busy = write(bob, vault, node, "general")
        assertEquals("busy", busy.code)
        assertTrue(busy.headers.getValue("Retry-After").toInt() in 1..2)
        assertEquals("pause_held", api.call(POST, "/write-pauses", bob, mapOf("vaultIds" to listOf(vault.value.toString()))).code)
        assertEquals(204, api.call(POST, "/write-pauses/release", alice, mapOf("vaultIds" to listOf(vault.value.toString()))).status)
        assertEquals(200, write(bob, vault, node, "general").status)

        val read = api.call(
            POST, "/vaults/batch-get", bob,
            mapOf("items" to listOf(mapOf("vaultId" to vault.value.toString()), mapOf("vaultId" to other.value.toString(), "afterSeq" to 1))),
        )
        assertEquals(listOf(true, false), read["items"].elements().map { it["found"].asBoolean() })

        val (rotation, _) = TestProtocol.logEntry(
            alice, other, head(alice, other).first + 1, head(alice, other).second, LogEntryKind.KEY_ROTATED, keyVersion = 2,
            keyCommitment = TestBlobs.random(32), checkpoint = checkpoint(alice, other),
        )
        val refused = api.call(
            POST, "/rotations/batch-apply", alice,
            mapOf(
                "items" to listOf(
                    mapOf(
                        "vaultId" to other.value.toString(),
                        "keyVersion" to 2,
                        "previousWrappedKey" to b64(TestBlobs.wrappedKey()),
                        "envelopes" to emptyList<Any>(),
                        "log" to listOf(CloakApi.log(rotation)),
                    ),
                ),
            ),
        )
        assertEquals("recipients_mismatch", refused.code)
        assertEquals(other.value.toString(), refused["vaultId"].asString())
    }

    @Test
    fun `sections are written, read, listed, moved and proved`() {
        val alice = registered()
        val vault = createVault(alice)
        val target = createVault(alice)
        val node = node(alice, vault)

        val first = write(alice, vault, node, "general")
        assertEquals(200, first.status)
        assertFalse(checkNotNull(first.body).has("ciphertext"), "a write echoes its header")
        assertTrue(checkNotNull(first.body).has("ciphertextHash"))
        assertEquals("version_conflict", write(alice, vault, node, "general", dataVersion = 1).code)
        val second = write(alice, vault, node, "general")
        assertEquals(first["writeHash"].asString(), second["previousWriteHash"].asString())

        val read = api.call(GET, "/vaults/${vault.value}/sections/${node.value}/general", alice)
        val feed = api.call(GET, "/vaults/${vault.value}/sections?afterChange=1", alice)
        assertEquals(2, read["dataVersion"].asInt())
        assertEquals(TestProtocol.sha256(bytes(read["ciphertext"].asString())), bytes(read["ciphertextHash"].asString()))
        assertEquals(1, feed["items"].size())
        assertEquals(2, feed["lastChangeSeq"].asLong())

        assertEquals(200, share(alice, target, node, "general").status)
        val (deletion, _) = signedWrite(alice, vault, node, "general", deleted = true)
        val (creation, _) = signedWrite(alice, target, node, "general")
        val moved = api.call(
            POST, "/sections/batch-write", alice,
            mapOf("items" to listOf(item(vault, node, "general", deletion), item(target, node, "general", creation))),
        )
        assertEquals(2, moved["items"].size())
        assertTrue(moved["items"].elements().none { it.has("ciphertext") })
        val headers = api.call(GET, "/vaults/${vault.value}/section-headers?limit=1000", alice)
        assertEquals(1, headers["items"].size())
        assertTrue(headers["items"][0]["deleted"].asBoolean())
        assertFalse(headers["items"][0].has("ciphertextHash"))
        assertEquals(3, headers["lastChangeSeq"].asLong())
        assertEquals("validation_failed", api.call(GET, "/vaults/${vault.value}/section-headers?limit=1001", alice).code)
        assertTrue(api.call(GET, "/vaults/${vault.value}/sections/${node.value}/general", alice)["deleted"].asBoolean())
        assertEquals(2, api.call(GET, "/nodes/${node.value}", alice)["sections"].size())
        val missing = Uuid.random().toString()
        assertEquals(listOf(missing), api.call(POST, "/nodes/batch-get", alice, mapOf("nodeIds" to listOf(node.value.toString(), missing)))["missingNodeIds"].elements().map { it.asString() })

        val bob = registered()
        addMember(alice, target, bob, Role.EDITOR)
        val (demotion, _) = entry(alice, target, LogEntryKind.MEMBER_ROLE_SET, bob, Role.VIEWER, checkpoint = checkpoint(alice, target))
        api.call(PATCH, "/vaults/${target.value}/members/${bob.id.value}", alice, mapOf("role" to "viewer", "log" to CloakApi.log(demotion)))
        val seq = head(alice, target).first
        val query = mapOf("checkpointSeq" to seq, "nodeId" to node.value.toString(), "sectionName" to "general")
        val proofs = api.call(
            POST, "/vaults/${target.value}/checkpoint-proofs/batch-get", alice,
            mapOf("items" to listOf(query, query + ("sectionName" to "other"))),
        )["items"]
        assertEquals(1, proofs[0]["size"].asInt())
        assertTrue(proofs[0].has("inclusion"))
        assertFalse(proofs[1].has("inclusion"))
        assertEquals(404, api.call(POST, "/vaults/${target.value}/checkpoint-proofs/batch-get", alice, mapOf("items" to listOf(query + ("checkpointSeq" to 1)))).status)
        assertEquals("/items/1", api.call(POST, "/vaults/${target.value}/checkpoint-proofs/batch-get", alice, mapOf("items" to listOf(query, query)))["errors"][0]["pointer"].asString())
        val leaves = api.call(GET, "/vaults/${target.value}/checkpoints/$seq/leaves", alice)
        assertEquals(1, leaves["size"].asInt())
        assertNull(leaves.body?.get("nextCursor"))
        assertEquals(node.value.toString(), leaves["leaves"][0]["nodeId"].asString())
        assertEquals(404, api.call(GET, "/vaults/${target.value}/checkpoints/1/leaves", alice).status)
        assertEquals(404, api.call(GET, "/vaults/${target.value}/checkpoints/x/leaves", alice).status)
        assertEquals("validation_failed", api.call(GET, "/vaults/${target.value}/checkpoints/$seq/leaves?cursor=nope", alice).code)
    }

    @Test
    fun `failures are problems with stable codes and pointers`() {
        val alice = registered()
        val vault = createVault(alice)
        val node = node(alice, vault)
        val (stale, _) = signedWrite(alice, vault, node, "general")
        addMember(alice, vault, registered(), Role.VIEWER)

        val staleHead = api.call(PUT, "/vaults/${vault.value}/sections/${node.value}/general", alice, CloakApi.write(stale))
        val badBase64 = api.call(PUT, "/vaults/${vault.value}/sections/${node.value}/general", alice, CloakApi.write(stale) + ("logHeadHash" to "%%%"))
        val notJson = api.call(POST, "/vaults", alice, "{")
        val malformedId = api.call(GET, "/vaults/not-a-uuid", alice)
        val (forged, _) = entry(alice, vault, LogEntryKind.MEMBER_ADDED, registered(), Role.VIEWER)
        val badSignature = api.call(
            POST, "/vaults/${vault.value}/members", alice,
            mapOf(
                "userId" to forged.subjectUserId!!.value.toString(), "role" to "viewer", "keyVersion" to 1, "userKeyVersion" to 1,
                "keyEnvelope" to b64(TestBlobs.envelope()), "log" to CloakApi.log(forged) + ("signature" to b64(TestBlobs.blob(65))),
            ),
        )

        assertEquals("stale_head", staleHead.code)
        // The vault's creation, the node's and the new member's: the head is at 3.
        assertEquals(3, staleHead["currentVersion"].asInt())
        assertEquals("/logHeadHash", badBase64["errors"][0]["pointer"].asString())
        assertEquals("validation_failed", notJson.code)
        assertEquals(404, malformedId.status)
        assertEquals("bad_signature", badSignature.code)
        assertNull(api.call(GET, "/vaults/${vault.value}", alice).body?.get("nope"))
        val planted = write(alice, createVault(alice), node, "general")
        assertEquals("not_shared", planted["errors"][0]["code"].asString())
        assertEquals("/nodeId", planted["errors"][0]["pointer"].asString())
    }

    @Test
    fun `nodes are created and shared by signed entries, and vaults deleted by one`() {
        val alice = registered()
        val bob = registered()
        val vault = createVault(alice)
        val team = createVault(alice)
        addMember(alice, team, bob, Role.VIEWER)
        val node = node(alice, vault)

        val shared = share(alice, team, node, "general")
        assertEquals(200, shared.status)
        val log = api.call(GET, "/vaults/${team.value}/log?afterSeq=2", bob)["items"][0]
        assertEquals("node_shared", log["kind"].asString())
        assertEquals(node.value.toString(), log["nodeId"].asString())
        assertEquals(vault.value.toString(), log["homeVaultId"].asString())
        assertEquals("general", log["sections"].asString())
        val written = write(alice, team, node, "general")
        assertEquals(origins.getValue(node).nodeKey.value, written["nodeKey"].asString())
        assertEquals(alice.id.value.toString(), written["ownerUserId"].asString())
        val (again, _) = entry(alice, vault, LogEntryKind.NODE_CREATED, nodeId = node, nodeKey = origins.getValue(node).nodeKey.value)
        assertEquals("log_rejected", api.call(POST, "/vaults/${vault.value}/node-entries", alice, mapOf("log" to CloakApi.log(again))).code)

        val (deletion, _) = entry(alice, team, LogEntryKind.VAULT_DELETED)
        assertEquals("role_required", api.call(POST, "/vaults/${team.value}/deletion", bob, mapOf("log" to CloakApi.log(deletion))).code)
        assertEquals(204, api.call(POST, "/vaults/${team.value}/deletion", alice, mapOf("log" to CloakApi.log(deletion))).status)
        assertTrue(api.call(GET, "/vaults/${team.value}", bob)["deleted"].asBoolean())
        assertEquals(404, api.call(GET, "/vaults/${team.value}/sections", alice).status)
        assertFalse(api.call(GET, "/vaults", alice)["items"].elements().any { it["id"].asString() == team.value.toString() })
    }

    @Test
    fun `a person added is pending until they accept the vault or its inviter`() {
        val alice = registered()
        val bob = registered()
        val first = createVault(alice)
        val second = createVault(alice)
        addMember(alice, first, bob, Role.VIEWER)

        val pending = api.call(GET, "/vaults/${first.value}", bob)
        assertFalse(pending["accepted"].asBoolean())
        assertEquals(alice.id.value.toString(), pending["addedByUserId"].asString())
        assertEquals(0, api.call(GET, "/vaults", bob)["items"].size())
        assertEquals(1, api.call(GET, "/vaults?pending=true", bob)["items"].size())
        assertEquals("validation_failed", api.call(GET, "/vaults?pending=maybe", bob).code)

        assertEquals(204, api.call(PUT, "/vaults/${first.value}/acceptance", bob).status)
        assertEquals(1, api.call(GET, "/vaults", bob)["items"].size())
        assertEquals(204, api.call(POST, "/invitations/acceptance", bob, mapOf("inviterUserId" to alice.id.value.toString())).status)
        addMember(alice, second, bob, Role.VIEWER)
        assertTrue(api.call(GET, "/vaults/${second.value}", bob)["accepted"].asBoolean())
        assertEquals(1000, api.call(GET, "/meta")["limits"]["maxPendingInvitations"].asInt())
    }

    @Test
    fun `credentials changes and identity deletion are signed`() {
        val alice = registered()
        val kdf = dev.voir.cloak.server.identity.domain.KdfParams(TestBlobs.random(16), 131_072, 4)
        val bundle = TestBlobs.blob(41 + 129)
        val signed = TestProtocol.credentialsChange(alice, 1, kdf, bundle)
        val change = mapOf("expectedCredentialsVersion" to 1, "kdf" to CloakApi.kdf(kdf), "privateKeyBundle" to b64(bundle))

        assertEquals("bad_signature", api.call(PUT, "/identity/credentials", alice, change + ("signature" to b64(alice.sign(bundle)))).code)
        assertEquals(2, api.call(PUT, "/identity/credentials", alice, change + ("signature" to b64(signed.signature)))["credentialsVersion"].asInt())

        val notAfter = java.time.Instant.now().epochSecond + 300
        val deletion = { version: Int -> b64(TestProtocol.identityDeletion(alice, version, notAfter).signature) }
        assertEquals(
            "credentials_version_conflict",
            api.call(POST, "/identity/deletion", alice, mapOf("credentialsVersion" to 1, "notAfter" to notAfter, "signature" to deletion(1))).code,
        )
        assertEquals(204, api.call(POST, "/identity/deletion", alice, mapOf("credentialsVersion" to 2, "notAfter" to notAfter, "signature" to deletion(2))).status)
        assertEquals("identity_deleted", api.call(GET, "/identity", alice).code)
    }

    /** Registers a new user. */
    private fun registered(): TestClient =
        TestClient().also { api.call(POST, "/identity", it, CloakApi.registration(it)) }

    /** The vault's head and key version as [reader] sees them. */
    private fun head(reader: TestClient, vault: VaultId): Triple<Long, ByteString, Int> {
        val view = api.call(GET, "/vaults/${vault.value}", reader)
        return Triple(view["logSeq"].asLong(), bytes(view["logHeadHash"].asString()), view["keyVersion"].asInt())
    }

    /** Signs one entry that continues the head [author] sees. */
    private fun entry(
        author: TestClient,
        vault: VaultId,
        kind: LogEntryKind,
        subject: TestClient? = null,
        role: Role? = null,
        checkpoint: ByteString? = null,
        nodeId: NodeId? = null,
        homeVaultId: VaultId? = null,
        nodeKey: String? = null,
        sections: String? = null,
    ) = head(author, vault).let { (seq, hash, keyVersion) ->
        TestProtocol.logEntry(
            author, vault, seq + 1, hash, kind, subject?.keys, role, keyVersion, checkpoint = checkpoint,
            nodeId = nodeId, homeVaultId = homeVaultId, nodeKey = nodeKey, sections = sections,
        )
    }

    /** Node origins this test created, by node id. */
    private val origins = mutableMapOf<NodeId, NodeOrigin>()

    /** Creates a node owned by [owner] in [vault], its home, with a signed `node_created`. */
    private fun node(owner: TestClient, vault: VaultId, key: String = Uuid.random().toString()): NodeId {
        val origin = NodeOrigin(owner.id, vault, NodeKey(key))
        val (log, _) = entry(owner, vault, LogEntryKind.NODE_CREATED, nodeId = origin.nodeId, nodeKey = key)
        val created = api.call(POST, "/vaults/${vault.value}/node-entries", owner, mapOf("log" to CloakApi.log(log)))
        check(created.status == 200) { "node failed: ${created.body}" }
        origins[origin.nodeId] = origin
        return origin.nodeId
    }

    /** Shares [sections] of [owner]'s node into [vault] with a signed `node_shared`. */
    private fun share(owner: TestClient, vault: VaultId, node: NodeId, sections: String): CloakApi.Response {
        val origin = origins.getValue(node)
        val (log, _) = entry(
            owner, vault, LogEntryKind.NODE_SHARED, nodeId = node, homeVaultId = origin.homeVaultId, nodeKey = origin.nodeKey.value, sections = sections,
        )
        return api.call(POST, "/vaults/${vault.value}/node-entries", owner, mapOf("log" to CloakApi.log(log)))
    }

    /** Creates a vault owned by [owner]. */
    private fun createVault(owner: TestClient): VaultId {
        val id = VaultId(Uuid.random())
        val (log, _) = TestProtocol.logEntry(owner, id, 1, null, LogEntryKind.VAULT_CREATED, owner.keys, Role.OWNER, 1, keyCommitment = TestBlobs.random(32))
        val created = api.call(POST, "/vaults", owner, mapOf("id" to id.value.toString(), "keyEnvelope" to b64(TestBlobs.envelope()), "log" to CloakApi.log(log)))
        check(created.status == 201) { "create failed: ${created.body}" }
        return id
    }

    /** Adds [user] as [role]. */
    private fun addMember(admin: TestClient, vault: VaultId, user: TestClient, role: Role): CloakApi.Response {
        val (log, _) = entry(admin, vault, LogEntryKind.MEMBER_ADDED, user, role)
        return api.call(
            POST, "/vaults/${vault.value}/members", admin,
            mapOf(
                "userId" to user.id.value.toString(), "role" to role.code, "keyVersion" to head(admin, vault).third,
                "userKeyVersion" to user.keys.keyVersion, "keyEnvelope" to b64(TestBlobs.envelope()), "log" to CloakApi.log(log),
            ),
        )
    }

    /** Signs the next write of a section against what the server shows. */
    private fun signedWrite(writer: TestClient, vault: VaultId, node: NodeId, name: String, deleted: Boolean = false, dataVersion: Long? = null) =
        head(writer, vault).let { (seq, hash, keyVersion) ->
            val latest = api.call(GET, "/vaults/${vault.value}/sections/${node.value}/$name", writer).takeIf { it.status == 200 }
            TestProtocol.sectionWrite(
                writer, SectionRef(vault, node, SectionName(name)), NodeType("compute.vps"), keyVersion,
                dataVersion ?: ((latest?.get("dataVersion")?.asLong() ?: 0) + 1), seq, hash,
                latest?.get("writeHash")?.asString()?.let(::bytes), if (deleted) null else TestBlobs.ciphertext(), origins.getValue(node),
            )
        }

    /** Writes the next version of a section. */
    private fun write(writer: TestClient, vault: VaultId, node: NodeId, name: String, dataVersion: Long? = null): CloakApi.Response {
        val (input, _) = signedWrite(writer, vault, node, name, dataVersion = dataVersion)
        return api.call(PUT, "/vaults/${vault.value}/sections/${node.value}/$name", writer, CloakApi.write(input))
    }

    /** One batch item. */
    private fun item(vault: VaultId, node: NodeId, name: String, input: dev.voir.cloak.server.section.domain.SectionWriteInput) =
        CloakApi.write(input) + mapOf("vaultId" to vault.value.toString(), "nodeId" to node.value.toString(), "sectionName" to name)

    /** The elements of a JSON array. */
    private fun tools.jackson.databind.JsonNode.elements(): List<tools.jackson.databind.JsonNode> = iterator().asSequence().toList()

    /** The checkpoint over the vault's latest writes, read through the change feed. */
    private fun checkpoint(reader: TestClient, vault: VaultId): ByteString {
        val items = api.call(GET, "/vaults/${vault.value}/sections?limit=100", reader)["items"]
        val leaves = items.elements().map {
            CheckpointLeaf(NodeId(Uuid.parse(it["nodeId"].asString())), SectionName(it["sectionName"].asString()), it["dataVersion"].asLong(), bytes(it["writeHash"].asString()))
        }
        return TestProtocol.checkpoint(leaves)
    }
}
