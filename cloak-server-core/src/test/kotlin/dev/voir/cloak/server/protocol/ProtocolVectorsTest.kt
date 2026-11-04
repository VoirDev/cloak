package dev.voir.cloak.server.protocol

import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Checks the server's encoding, signed messages, strict signatures, log rules and checkpoints
 * against the shared test vectors in `cloak-protocol/test-vectors/v1`, which every client must
 * also pass, so the server refuses exactly what members refuse.
 */
class ProtocolVectorsTest {
    @TestFactory
    fun `canonical encoding matches every vector`(): List<DynamicTest> =
        vectors("encoding.json").array("cases").map { case ->
            DynamicTest.dynamicTest(case.string("name")) {
                assertEquals(case.string("expected"), encode(case.array("fields")).hex())
            }
        }

    @TestFactory
    fun `strict Ed25519 gives every vector verdict`(): List<DynamicTest> =
        vectors("signatures.json").array("cases").map { case ->
            DynamicTest.dynamicTest(case.string("name")) {
                val refusal = StrictEd25519.check(case.bytes("publicKey"), case.bytes("message"), case.bytes("signature"))
                assertEquals(case.optionalString("reason"), refusal?.code)
            }
        }

    @Test
    fun `fingerprints and key statements match and verify`() {
        val identity = vectors("identity.json")
        identity.array("identities").forEach { json ->
            assertEquals(json.string("keysDigest"), Messages.keysDigest(keysOf(json)).hex())
        }
        identity.array("statements").forEach { json ->
            val keys = KEYS.keys(UserId(Uuid.parse(json.string("userId"))), json.int("keyVersion"))!!
            val previous = json.string("previousKeysDigest").let { ByteString(it.unhex()).takeIf { d -> !isAbsent(d) } }
            val message = Messages.keyStatement(keys, previous)
            assertEquals(json.string("message"), message.hex())
            assertNull(StrictEd25519.check(keys.signingPublicKey, message, json.bytes("signature")))
        }
    }

    @Test
    fun `user ids derive from host user ids as UUIDv5`() {
        val identity = vectors("identity.json")
        assertEquals(identity.string("userNamespace"), UserId.NAMESPACE.toString())
        identity.array("userIds").forEach { json ->
            val host = HostUserId.of(json.string("hostUserId"))
            assertEquals(json.string("userId"), host.userId.value.toString())
        }
    }

    @Test
    fun `node ids derive from owner, home vault and key as UUIDv5`() {
        vectors("identity.json").array("nodeIds").forEach { json ->
            val origin = NodeOrigin(
                UserId(Uuid.parse(json.string("ownerUserId"))),
                VaultId(Uuid.parse(json.string("homeVaultId"))),
                NodeKey(json.string("nodeKey")),
            )
            assertEquals(json.string("nodeId"), origin.nodeId.value.toString())
        }
    }

    @Test
    fun `credentials changes and identity deletions are signed as the vectors say`() {
        val credentials = vectors("identity.json").obj("credentials")
        val signer = credentials.obj("signer")
        val userId = UserId(Uuid.parse(signer.string("userId")))
        val keys = KEYS.keys(userId, signer.int("keyVersion"))!!
        val change = credentials.obj("change")
        val kdf = change.obj("kdf")
        val changeMessage = Messages.credentials(
            userId,
            keys.keyVersion,
            change.int("credentialsVersion"),
            change.bytes("privateKeyBundle"),
            KdfParams(kdf.bytes("salt"), kdf.int("memoryKib"), kdf.int("iterations"), kdf.int("parallelism")),
        )
        assertEquals(change.string("message"), changeMessage.hex())
        assertNull(StrictEd25519.check(keys.signingPublicKey, changeMessage, change.bytes("signature")))
        val deletion = credentials.obj("deletion")
        val deletionMessage = Messages.identityDeletion(userId, keys.keyVersion, deletion.int("credentialsVersion"), deletion.long("notAfter"))
        assertEquals(deletion.string("message"), deletionMessage.hex())
        assertNull(StrictEd25519.check(keys.signingPublicKey, deletionMessage, deletion.bytes("signature")))
    }

    @Test
    fun `host user ids are 1 to 255 bytes of well-formed Unicode`() {
        assertFailsWith<IllegalArgumentException> { HostUserId.of("") }
        assertFailsWith<IllegalArgumentException> { HostUserId.of("é".repeat(128)) }
        assertFailsWith<IllegalArgumentException> { HostUserId.of("\uD800") }
        assertEquals(255, HostUserId.of("x".repeat(255)).value.length)
    }

    @TestFactory
    fun `the scenario log passes the log rules and every negative log is refused`(): List<DynamicTest> {
        val log = vectors("vault-log.json")
        val vaultId = VaultId(Uuid.parse(log.string("vaultId")))
        val scenario = DynamicTest.dynamicTest("scenario") {
            log.array("log").forEach { json ->
                val fields = toFields(json)!!
                assertEquals(json.string("message"), Messages.logEntry(fields).hex())
                assertEquals(json.string("entryHash"), sha256(Messages.logEntry(fields)).hex())
            }
            val result = replay(vaultId, log.array("log"))
            assertNull(result, "the scenario log must pass, got $result")
        }
        val negatives = log.array("negatives").map { negative ->
            DynamicTest.dynamicTest(negative.string("name")) {
                assertEquals(negative.string("reason") to negative.long("failSeq"), replay(vaultId, negative.array("log")))
            }
        }
        return listOf(scenario) + negatives
    }

    @Test
    fun `an owner's vault_deleted ends the log, and nothing may follow`() {
        val log = vectors("vault-log.json")
        val vaultId = VaultId(Uuid.parse(log.string("vaultId")))
        val deletion = vectors("sections.json").obj("afterDeletion").obj("entry")
        assertNull(replay(vaultId, log.array("log") + deletion), "the log ending in vault_deleted must pass")
    }

    @TestFactory
    fun `checkpoint trees, paths and proofs match every vector`(): List<DynamicTest> {
        val checkpoints = vectors("checkpoints.json")
        val trees = checkpoints.array("trees").map { tree ->
            DynamicTest.dynamicTest("tree of ${tree.int("size")}") {
                val leaves = tree.array("leaves").map(::toLeaf)
                assertEquals(tree.string("root"), Merkle.root(leaves.reversed().sortedWith(Merkle.sectionOrder)).hex())
                val hashes = leaves.map(Merkle::leafHash)
                tree.array("leaves").forEachIndexed { index, json ->
                    assertEquals(json.string("leafData"), Merkle.leafData(leaves[index]).hex())
                    val path = MerkleTree(hashes).auditPath(index)
                    assertEquals(json["path"]!!.jsonArray.map { it.jsonPrimitive.content }, path.map { it.hex() })
                    assertTrue(Merkle.verifyInclusion(index.toLong(), leaves.size.toLong(), hashes[index], path, tree.bytes("root")))
                }
            }
        }
        val negatives = checkpoints.array("negatives").map { negative ->
            DynamicTest.dynamicTest(negative.string("name")) {
                val path = negative["path"]!!.jsonArray.map { ByteString(it.jsonPrimitive.content.unhex()) }
                assertFalse(
                    Merkle.verifyInclusion(negative.long("index"), negative.long("size"), negative.bytes("leafHash"), path, negative.bytes("root")),
                )
            }
        }
        return trees + negatives
    }

    @TestFactory
    fun `section write messages and hashes match every vector`(): List<DynamicTest> =
        vectors("sections.json").array("cases").map { case ->
            DynamicTest.dynamicTest(case.string("name")) {
                val write = case.obj("write")
                val previous = ByteString(write.string("previousWriteHash").unhex())
                val fields = SectionWriteFields(
                    vaultId = VaultId(Uuid.parse(write.string("vaultId"))),
                    nodeId = NodeId(Uuid.parse(write.string("nodeId"))),
                    nodeType = NodeType(write.string("nodeType")),
                    origin = NodeOrigin(
                        UserId(Uuid.parse(write.string("ownerUserId"))),
                        VaultId(Uuid.parse(write.string("homeVaultId"))),
                        NodeKey(write.string("nodeKey")),
                    ),
                    sectionName = SectionName(write.string("sectionName")),
                    vaultKeyVersion = write.int("vaultKeyVersion"),
                    dataVersion = write.long("dataVersion"),
                    deleted = write.int("deleted") == 1,
                    logSeq = write.long("logSeq"),
                    logHeadHash = write.bytes("logHeadHash"),
                    previousWriteHash = previous.takeIf { !isAbsent(it) },
                    writerUserId = UserId(Uuid.parse(write.string("writerUserId"))),
                    writerKeyVersion = write.int("writerKeyVersion"),
                    ciphertextHash = case.optionalString("ciphertext")?.let { sha256(ByteString(it.unhex())) },
                )
                val message = Messages.sectionWrite(fields)
                // The header's digest stands in for the ciphertext; zeros for a deletion.
                assertEquals(write.string("ciphertextHash"), (fields.ciphertextHash ?: ByteString(ByteArray(32))).hex())
                assertEquals(case.string("message"), message.hex())
                assertEquals(case.string("writeHash"), sha256(message).hex())
            }
        }

    /** Key versions of identity.json, as a server that holds them all. */
    private object KEYS : KeyDirectory {
        /** Every vector key version. */
        private val all: Map<Pair<UserId, Int>, PublicKeys> =
            vectors("identity.json").array("identities").map(::keysOf).associateBy { it.userId to it.keyVersion }

        override fun keys(userId: UserId, keyVersion: Int): PublicKeys? = all[userId to keyVersion]

        override fun isSuperseded(userId: UserId, keyVersion: Int): Boolean = false
    }

    /**
     * Replays a vector log request by request; returns the first violation, or `null`. Served
     * checkpoint leaves are checked against the signed root once their entry passed the rules, as
     * a member checks them.
     */
    private fun replay(vaultId: VaultId, log: List<JsonObject>): Pair<String, Long>? {
        var state = LogState.empty(vaultId)
        val request = mutableListOf<Pair<SignedLogEntry, List<CheckpointLeaf>?>>()
        fun applyRequest(): Pair<String, Long>? {
            try {
                state = LogRules.applyRequest(state, request.map { it.first }, KEYS).last()
            } catch (violation: LogViolation) {
                return violation.reason to violation.seq
            }
            val badLeaves = request.firstOrNull { (entry, leaves) ->
                leaves != null && Merkle.root(leaves.sortedWith(Merkle.sectionOrder)) != entry.fields.checkpoint
            }
            request.clear()
            return badLeaves?.let { "bad_checkpoint" to it.first.fields.seq }
        }
        for (json in log) {
            val fields = toFields(json) ?: return "bad_flag" to json.obj("entry").long("seq")
            val leaves = json["checkpointLeaves"]?.jsonArray?.map { toLeaf(it.jsonObject) }
            request += SignedLogEntry(fields, json.bytes("signature")) to leaves
            if (fields.requestEnd) applyRequest()?.let { return it }
        }
        return if (request.isEmpty()) null else applyRequest()
    }

    /** The signed fields of a vector entry, or `null` when its `requestEnd` is not a flag. */
    private fun toFields(json: JsonObject): LogFields? {
        val entry = json.obj("entry")
        val requestEnd = entry.int("requestEnd")
        if (requestEnd != 0 && requestEnd != 1) return null
        return LogFields(
            vaultId = VaultId(Uuid.parse(entry.string("vaultId"))),
            seq = entry.long("seq"),
            previousHash = ByteString(json.string("previousHash").unhex()).takeIf { !isAbsent(it) },
            kind = LogEntryKind.fromCode(entry.string("kind")),
            subjectUserId = entry.optionalString("subjectUserId")?.let { UserId(Uuid.parse(it)) },
            role = entry.optionalString("role")?.let(Role::fromCode),
            keyVersion = entry.int("keyVersion"),
            subjectKeys = entry.optionalString("subjectKeys")?.let { ByteString(it.unhex()) },
            subjectKeyVersion = entry["subjectKeyVersion"]?.jsonPrimitive?.int,
            keyCommitment = entry.optionalString("keyCommitment")?.let { ByteString(it.unhex()) },
            checkpoint = entry.optionalString("checkpoint")?.let { ByteString(it.unhex()) },
            requestEnd = requestEnd == 1,
            authorUserId = UserId(Uuid.parse(entry.string("authorUserId"))),
            authorKeyVersion = entry.int("authorKeyVersion"),
            nodeId = entry.optionalString("nodeId")?.let { NodeId(Uuid.parse(it)) },
            homeVaultId = entry.optionalString("homeVaultId")?.let { VaultId(Uuid.parse(it)) },
            nodeKey = entry.optionalString("nodeKey").orEmpty(),
            sections = entry.optionalString("sections").orEmpty(),
        )
    }

    /** Helpers for reading vectors. */
    private companion object {
        /** Directory of the shared vectors, set by the build. */
        val DIRECTORY = File(checkNotNull(System.getProperty("cloak.vectors")) { "Set the cloak.vectors system property" })

        /** Reads one vector file. */
        fun vectors(name: String): JsonObject = Json.parseToJsonElement(File(DIRECTORY, name).readText()).jsonObject

        /** Public keys of a vector identity. */
        fun keysOf(json: JsonObject): PublicKeys =
            PublicKeys(
                userId = UserId(Uuid.parse(json.string("userId"))),
                keyVersion = json.int("keyVersion"),
                cryptoSuite = 1,
                encryptionPublicKey = json.bytes("encryptionPublicKey"),
                signingPublicKey = json.bytes("signingPublicKey"),
                recoverySigningPublicKey = json.bytes("recoverySigningPublicKey"),
            )

        /** A checkpoint leaf of a vector. */
        fun toLeaf(json: JsonObject): CheckpointLeaf =
            CheckpointLeaf(
                nodeId = NodeId(Uuid.parse(json.string("nodeId"))),
                sectionName = SectionName(json.string("sectionName")),
                dataVersion = json.long("dataVersion"),
                writeHash = json.bytes("writeHash"),
            )

        /** Encodes typed vector fields. */
        fun encode(fields: List<JsonObject>): ByteString =
            fields.fold(Canonical()) { builder, field ->
                val value = field["value"]!!.jsonPrimitive
                when (field.string("type")) {
                    "label", "str" -> builder.str(value.content)
                    "u8" -> builder.u8(value.int)
                    "u32" -> builder.u32(value.int)
                    "u64" -> builder.u64(value.content.toULong())
                    "flag" -> builder.flag(value.int == 1)
                    "uuid" -> builder.uuid(Uuid.parse(value.content))
                    "key32" -> builder.key32(ByteString(value.content.unhex()))
                    "digest32" -> builder.digest32(ByteString(value.content.unhex()))
                    else -> error("Unknown field type")
                }
            }.build()

        fun JsonObject.obj(key: String): JsonObject = this[key]!!.jsonObject

        fun JsonObject.array(key: String): List<JsonObject> = this[key]!!.jsonArray.map(JsonElement::jsonObject)

        fun JsonObject.string(key: String): String = this[key]!!.jsonPrimitive.content

        fun JsonObject.optionalString(key: String): String? = this[key]?.takeIf { it != JsonNull }?.jsonPrimitive?.contentOrNull

        fun JsonObject.int(key: String): Int = this[key]!!.jsonPrimitive.int

        fun JsonObject.long(key: String): Long = this[key]!!.jsonPrimitive.long

        fun JsonObject.bytes(key: String): ByteString = ByteString(string(key).unhex())

        fun String.unhex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        fun ByteString.hex(): String = toByteArray().joinToString("") { "%02x".format(it) }
    }
}
