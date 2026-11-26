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
        assertEquals(8 * 1_048_576, meta["limits"]["maxPageBytes"].asInt())
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
        assertEquals(204, api.call(PUT, "/vaults/${vault.value}/acceptance", bob, CloakApi.acceptance(bob.vaultAcceptance(vault))).status)
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
        val asked = listOf("general", "absent").map { mapOf("vaultId" to vault.value.toString(), "nodeId" to node.value.toString(), "sectionName" to it) }
        val latest = api.call(POST, "/section-headers/batch-get", alice, mapOf("sections" to asked))
        assertEquals(headers["items"][0], latest["items"][0])
        assertEquals(1, latest["items"].size())
        assertEquals("absent", latest["missing"][0]["sectionName"].asString())
        assertEquals("/sections/1", api.call(POST, "/section-headers/batch-get", alice, mapOf("sections" to listOf(asked[0], asked[0])))["errors"][0]["pointer"].asString())

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
    fun `reads that carry ciphertext page within one budget, and their cursors cover everything once`() {
        val alice = registered()
        val vault = createVault(alice)
        val large = node(alice, vault)
        val small = node(alice, vault)
        val names = (1..9).map { "large_$it" }
        names.forEach { assertEquals(200, write(alice, vault, large, it, blocks = LARGEST_BLOCKS).status) }
        write(alice, vault, small, "general")
        val budget = api.call(GET, "/meta")["limits"]["maxPageBytes"].asInt()
        fun bytesOf(sections: tools.jackson.databind.JsonNode) = sections.elements().sumOf { bytes(it["ciphertext"].asString()).size }

        val first = api.call(GET, "/nodes/${large.value}", alice)
        val cursor = first["nextCursor"].asString()
        val second = api.call(GET, "/nodes/${large.value}?cursor=$cursor", alice)
        assertTrue(bytesOf(first["sections"]) <= budget)
        assertNull(second.body?.get("nextCursor"))
        assertEquals(names, (first["sections"].elements() + second["sections"].elements()).map { it["sectionName"].asString() })
        assertEquals("validation_failed", api.call(GET, "/nodes/${small.value}?cursor=$cursor", alice).code)

        val missing = Uuid.random().toString()
        val ids = listOf(large, small).map { it.value.toString() }.sorted()
        val batch = api.call(POST, "/nodes/batch-get", alice, mapOf("nodeIds" to ids + missing))
        assertEquals(200, batch.status)
        assertTrue(batch["items"].elements().sumOf { bytesOf(it["sections"]) } <= budget)
        // Nodes fill the budget in id order; the larger node either carries a cursor or is left unread.
        val reached = batch["items"].elements().associateBy { it["nodeId"].asString() }
        val unread = batch["unreadNodeIds"].elements().map { it.asString() }
        assertTrue(reached.values.any { it.has("nextCursor") } || unread.isNotEmpty())
        assertEquals((ids + missing).toSet(), reached.keys + unread + batch["missingNodeIds"].elements().map { it.asString() })

        val feed = generateSequence(api.call(GET, "/vaults/${vault.value}/sections?limit=100", alice)) { page ->
            page.takeIf { it["throughChangeSeq"].asLong() < it["lastChangeSeq"].asLong() }
                ?.let { api.call(GET, "/vaults/${vault.value}/sections?limit=100&afterChange=${it["throughChangeSeq"].asLong()}", alice) }
        }.toList()
        assertTrue(feed.size >= 2)
        feed.forEach { assertTrue(bytesOf(it["items"]) <= budget) }
        assertEquals(names + "general", feed.flatMap { page -> page["items"].elements().map { it["sectionName"].asString() } })
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
    fun `a body is read as strictly as the contract types it`() {
        val alice = registered()
        val vault = createVault(alice)
        val node = node(alice, vault)
        val (input, _) = signedWrite(alice, vault, node, "general")
        val valid = CloakApi.write(input)
        val path = "/vaults/${vault.value}/sections/${node.value}/general"
        val mistyped = listOf(
            "/dataVersion" to input.dataVersion.toString(),
            "/dataVersion" to input.dataVersion + 0.9,
            "/deleted" to "false",
            "/deleted" to 0,
            "/nodeType" to 7,
            "/nodeType" to 7.5,
            "/nodeType" to true,
        )

        for ((pointer, value) in mistyped) {
            val response = api.call(PUT, path, alice, valid + (pointer.removePrefix("/") to value))
            assertEquals(400, response.status, "$pointer = $value")
            assertEquals("validation_failed", response.code, "$pointer = $value")
            assertEquals(pointer, response["errors"][0]["pointer"].asString(), "$pointer = $value")
            assertEquals("schema", response["errors"][0]["code"].asString(), "$pointer = $value")
        }
        val repeated = "{\"dataVersion\":${input.dataVersion}," + mapper.writeValueAsString(valid).removePrefix("{")
        val duplicate = api.call(PUT, path, alice, repeated)
        assertEquals(400, duplicate.status)
        assertEquals("validation_failed", duplicate.code)
        assertEquals(200, api.call(PUT, path, alice, valid + ("unknown" to true)).status)
    }

    @Test
    fun `path ids are taken only in their canonical lowercase hyphenated form`() {
        val alice = registered()
        val vault = createVault(alice)
        val node = node(alice, vault)
        write(alice, vault, node, "general")
        val spellings = { id: Uuid -> listOf(id.toString().uppercase(), id.toString().replace("-", "")) }

        assertEquals(200, api.call(GET, "/vaults/${vault.value}", alice).status)
        assertEquals(200, api.call(GET, "/nodes/${node.value}", alice).status)
        assertEquals(200, api.call(GET, "/users/${alice.id.value}/keys", alice).status)
        val refused = spellings(vault.value).map { "/vaults/$it" } +
            spellings(node.value).map { "/nodes/$it" } +
            spellings(alice.id.value).map { "/users/$it/keys" }
        for (path in refused) {
            val response = api.call(GET, path, alice)
            assertEquals(404, response.status, path)
            assertEquals("not_found", response.code, path)
        }
    }

    @Test
    fun `body ids are taken only in their canonical lowercase hyphenated form`() {
        val alice = registered()
        val vault = createVault(alice)
        val node = node(alice, vault)
        write(alice, vault, node, "general")
        val asked = { vaultId: Any, nodeId: Any -> mapOf("sections" to listOf(mapOf("vaultId" to vaultId, "nodeId" to nodeId, "sectionName" to "general"))) }

        assertEquals(200, api.call(POST, "/nodes/batch-get", alice, mapOf("nodeIds" to listOf(node.value.toString()))).status)
        assertEquals(1, api.call(POST, "/section-headers/batch-get", alice, asked(vault.value.toString(), node.value.toString()))["items"].size())
        for (spelling in otherSpellings(node.value) + listOf(42)) {
            val nodes = api.call(POST, "/nodes/batch-get", alice, mapOf("nodeIds" to listOf(spelling)))
            assertEquals("validation_failed", nodes.code, "$spelling")
            assertEquals("/nodeIds/0", nodes["errors"][0]["pointer"].asString(), "$spelling")
            val headers = api.call(POST, "/section-headers/batch-get", alice, asked(vault.value.toString(), spelling))
            assertEquals("validation_failed", headers.code, "$spelling")
            assertEquals("/sections/0/nodeId", headers["errors"][0]["pointer"].asString(), "$spelling")
        }
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

        val (seq, hash, keyVersion) = head(alice, vault)
        var previous = hash
        val batch = listOf("batch-a", "batch-b").mapIndexed { index, key ->
            val origin = NodeOrigin(alice.id, vault, NodeKey(key))
            origins[origin.nodeId] = origin
            val (input, entryHash) = TestProtocol.logEntry(
                alice, vault, seq + 1 + index, previous, LogEntryKind.NODE_CREATED, keyVersion = keyVersion, nodeId = origin.nodeId, nodeKey = key,
            )
            previous = entryHash
            input
        }
        val appended = api.call(POST, "/vaults/${vault.value}/node-entries/batch-append", alice, mapOf("log" to batch.map(CloakApi::log)))
        assertEquals(seq + 2, appended["logSeq"].asLong())
        val unshare = api.call(POST, "/vaults/${vault.value}/node-entries/batch-append", alice, mapOf("log" to listOf(CloakApi.log(again.copy(kind = LogEntryKind.NODE_UNSHARED)))))
        assertEquals("/log/0/kind", unshare["errors"][0]["pointer"].asString())
        assertEquals(200, write(alice, vault, checkNotNull(batch.last().nodeId), "general").status)

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
        assertFalse(checkNotNull(pending.body).has("acceptance"))
        assertEquals(alice.id.value.toString(), pending["addedByUserId"].asString())
        assertEquals(0, api.call(GET, "/vaults", bob)["items"].size())
        assertEquals(1, api.call(GET, "/vaults?pending=true", bob)["items"].size())
        assertEquals("validation_failed", api.call(GET, "/vaults?pending=maybe", bob).code)

        val forged = CloakApi.acceptance(bob.vaultAcceptance(second))
        assertEquals("bad_signature", api.call(PUT, "/vaults/${first.value}/acceptance", bob, forged).code)
        assertEquals(204, api.call(PUT, "/vaults/${first.value}/acceptance", bob, CloakApi.acceptance(bob.vaultAcceptance(first))).status)
        assertEquals(1, api.call(GET, "/vaults", bob)["items"].size())
        val own = api.call(GET, "/vaults/${first.value}", bob)["acceptance"]
        assertEquals(1, own["keyVersion"].asInt())
        assertEquals(b64(bob.vaultAcceptance(first).signature), own["signature"].asString())
        assertNull(own["inviterUserId"])
        val inviter = bob.inviterAcceptance(alice.id)
        val acceptInviter = mapOf("inviterUserId" to alice.id.value.toString()) + CloakApi.acceptance(inviter)
        assertEquals(204, api.call(POST, "/invitations/acceptance", bob, acceptInviter).status)
        addMember(alice, second, bob, Role.VIEWER)
        val later = api.call(GET, "/vaults/${second.value}", bob)
        assertTrue(later["accepted"].asBoolean())
        assertEquals(alice.id.value.toString(), later["acceptance"]["inviterUserId"].asString())
        assertEquals(b64(inviter.signature), later["acceptance"]["signature"].asString())
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
        val created = api.call(
            POST, "/vaults", owner,
            mapOf(
                "id" to id.value.toString(), "keyEnvelope" to b64(TestBlobs.envelope()), "log" to CloakApi.log(log),
                "acceptance" to CloakApi.acceptance(owner.vaultAcceptance(id)),
            ),
        )
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
    private fun signedWrite(writer: TestClient, vault: VaultId, node: NodeId, name: String, deleted: Boolean = false, dataVersion: Long? = null, blocks: Int = 1) =
        head(writer, vault).let { (seq, hash, keyVersion) ->
            val latest = api.call(GET, "/vaults/${vault.value}/sections/${node.value}/$name", writer).takeIf { it.status == 200 }
            TestProtocol.sectionWrite(
                writer, SectionRef(vault, node, SectionName(name)), NodeType("compute.vps"), keyVersion,
                dataVersion ?: ((latest?.get("dataVersion")?.asLong() ?: 0) + 1), seq, hash,
                latest?.get("writeHash")?.asString()?.let(::bytes), if (deleted) null else TestBlobs.ciphertext(blocks), origins.getValue(node),
            )
        }

    /** Writes the next version of a section. */
    private fun write(writer: TestClient, vault: VaultId, node: NodeId, name: String, dataVersion: Long? = null, blocks: Int = 1): CloakApi.Response {
        val (input, _) = signedWrite(writer, vault, node, name, dataVersion = dataVersion, blocks = blocks)
        return api.call(PUT, "/vaults/${vault.value}/sections/${node.value}/$name", writer, CloakApi.write(input))
    }

    /** One batch item. */
    private fun item(vault: VaultId, node: NodeId, name: String, input: dev.voir.cloak.server.section.domain.SectionWriteInput) =
        CloakApi.write(input) + mapOf("vaultId" to vault.value.toString(), "nodeId" to node.value.toString(), "sectionName" to name)

    private companion object {
        /** Padding blocks of the largest section: 41 + 256 × 4095 bytes, just under 1 MiB. */
        const val LARGEST_BLOCKS = 4_095

        /** Spellings of [id] Jackson or a lenient parser would take, which the contract does not. */
        fun otherSpellings(id: Uuid): List<String> =
            listOf(
                id.toString().uppercase(),
                id.toString().replace("-", ""),
                java.util.Base64.getEncoder().encodeToString(id.toByteArray()),
            )
    }

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
