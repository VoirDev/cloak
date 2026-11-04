package dev.voir.cloak.spring

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.testing.TestProtocol
import dev.voir.cloak.spring.CloakApi.Companion.b64
import dev.voir.cloak.spring.guard.CloakRequestGuard
import dev.voir.cloak.spring.testhost.CloakTestApplication
import dev.voir.cloak.spring.web.CloakOperation
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.health.contributor.HealthIndicator
import org.springframework.boot.health.contributor.Status
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.system.CapturedOutput
import org.springframework.boot.test.system.OutputCaptureExtension
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.http.HttpMethod.GET
import org.springframework.http.HttpMethod.POST
import org.springframework.http.HttpMethod.PUT
import org.springframework.test.web.servlet.MockMvc
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping
import tools.jackson.databind.json.JsonMapper
import java.time.Duration
import java.util.Collections
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * How the starter admits requests before any operation runs: the size limit, the caller, the
 * host's guard and deleted users; and what it reports about them: logs, meters and health. The
 * request limit is set to its floor, 4MB, which the largest legitimate requests must still fit.
 */
@SpringBootTest(
    classes = [CloakTestApplication::class, CloakAdmissionTest.GuardedHost::class],
    properties = ["cloak.max-request-size=4MB"],
)
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension::class)
class CloakAdmissionTest {
    @Autowired
    private lateinit var mvc: MockMvc

    @Autowired
    private lateinit var mapper: JsonMapper

    @Autowired
    private lateinit var meters: MeterRegistry

    @Autowired
    private lateinit var guard: RecordingGuard

    @Autowired
    @Qualifier("cloak")
    private lateinit var health: HealthIndicator

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private lateinit var mappings: RequestMappingHandlerMapping

    private lateinit var api: CloakApi

    @BeforeTest
    fun setUp() {
        api = CloakApi(mvc, mapper)
    }

    @Test
    fun `every handler names the operation the contract gives its method and path`() {
        val byRoute = OpenApiContract.specOperations.associate { (it.method to OpenApiContract.normalize(it.template)) to it.operationId }
        val named = mappings.handlerMethods.flatMap { (info, handler: HandlerMethod) ->
            info.pathPatternsCondition?.patternValues.orEmpty().filter { it.startsWith("/cloak/v1/") }.flatMap { path ->
                info.methodsCondition.methods.map { method ->
                    (method.name to OpenApiContract.normalize(path.removePrefix("/cloak/v1"))) to
                        handler.getMethodAnnotation(CloakOperation::class.java)?.value
                }
            }
        }.toMap()

        assertEquals(byRoute, named)
    }

    @Test
    fun `a deleted user is refused by every operation of the contract, whatever the request holds`() {
        val alice = registered()
        val deletion = TestProtocol.identityDeletion(alice, 1, java.time.Instant.now().epochSecond + 300)
        val body = mapOf("credentialsVersion" to 1, "notAfter" to deletion.notAfter, "signature" to CloakApi.b64(deletion.signature))
        assertEquals(204, api.call(POST, "/identity/deletion", alice, body).status)

        for (operation in OpenApiContract.specOperations) {
            val path = operation.template
                .replace("{seq}", "1")
                .replace("{sectionName}", "general")
                .replace(Regex("\\{[^}]+}"), Uuid.random().toString())
            val response = api.call(HttpMethod.valueOf(operation.method), path, alice, if (operation.hasBody) "{}" else null)
            val expected = if (operation.operationId == "getMeta") 200 else 410
            assertEquals(expected, response.status, operation.operationId)
            if (expected == 410) assertEquals("identity_deleted", response.code, operation.operationId)
        }
    }

    @Test
    fun `the host's guard sees the caller and the operation only, and its refusal says when to retry`() {
        val limited = TestClient(dev.voir.cloak.server.identity.domain.HostUserId.of("limited-${Uuid.random()}"))
        guard.calls.clear()

        val refused = api.call(GET, "/vaults", limited)
        api.call(GET, "/meta")

        assertEquals(429, refused.status)
        assertEquals("rate_limited", refused.code)
        assertEquals("2", refused.headers["Retry-After"])
        assertEquals(listOf(limited.hostUserId.value to "listVaults"), guard.calls.toList())
    }

    @Test
    fun `a body over the limit is refused before it is read`() {
        val alice = registered()
        val body = "x".repeat(Limits.MIN_REQUEST_BYTES + 1)

        val response = api.call(POST, "/vaults", alice, body)

        assertEquals(413, response.status)
        assertEquals("payload_too_large", response.code)
    }

    @Test
    fun `the largest rotation, key replacement and section write fit within the floor of the limit`() {
        val alice = registered()
        val vault = Uuid.random()
        val leftOut = List(Limits.MAX_LEFT_OUT) {
            mapOf("nodeId" to Uuid.random().toString(), "sectionName" to "a".repeat(64), "writeHash" to b64(TestBlobs.random(32)))
        }
        val rotation = mapOf(
            "keyVersion" to Int.MAX_VALUE,
            "previousWrappedKey" to b64(TestBlobs.wrappedKey()),
            "envelopes" to List(Limits.MAX_MEMBERS_PER_VAULT) {
                mapOf("userId" to Uuid.random().toString(), "userKeyVersion" to Int.MAX_VALUE, "keyEnvelope" to b64(TestBlobs.envelope()))
            },
            "log" to List(Limits.MAX_MEMBERS_PER_VAULT) { longestEntry("member_keys_replaced") } + longestEntry("key_rotated"),
            "leftOut" to leftOut,
        )
        val replacement = mapOf(
            "log" to longestEntry("member_keys_replaced"),
            "keyEnvelope" to b64(TestBlobs.envelope()),
            "leftOut" to leftOut,
        )
        val section = mapOf(
            "nodeType" to "a".repeat(64), "vaultKeyVersion" to Int.MAX_VALUE, "dataVersion" to Long.MAX_VALUE, "deleted" to false,
            "logSeq" to Long.MAX_VALUE, "logHeadHash" to b64(TestBlobs.random(32)), "previousWriteHash" to b64(TestBlobs.random(32)),
            "writerKeyVersion" to Int.MAX_VALUE, "ciphertext" to b64(TestBlobs.ciphertext(4_095)),
            "signature" to b64(TestBlobs.blob(65)),
        )
        val requests = listOf(
            Triple(POST, "/vaults/$vault/rotations", rotation),
            Triple(POST, "/vaults/$vault/key-replacements", replacement),
            Triple(PUT, "/vaults/$vault/sections/${Uuid.random()}/general", section),
        )

        for ((method, path, body) in requests) {
            val json = mapper.writeValueAsString(body)
            assertTrue(json.length <= Limits.MIN_REQUEST_BYTES, "$path is ${json.length} bytes")
            assertNotEquals(413, api.call(method, path, alice, json).status, path)
        }
    }

    @Test
    fun `a suspicious refusal is logged by operation and code, never by who`(output: CapturedOutput) {
        val mallory = TestClient()
        val forged = CloakApi.registration(mallory) + ("signature" to b64(TestBlobs.blob(65)))

        assertEquals("bad_signature", api.call(POST, "/identity", mallory, forged).code)

        assertTrue("Cloak refused registerIdentity: bad_signature" in output.out, output.out)
        assertFalse(mallory.hostUserId.value in output.all)
        assertFalse(mallory.id.value.toString() in output.all)
    }

    @Test
    fun `operations become meters whose tags never carry an id`() {
        val alice = registered()
        api.call(GET, "/identity", alice)
        api.call(GET, "/vaults/${Uuid.random()}", alice)

        assertNotNull(meters.find("cloak.requests").tags("operation", "getIdentity", "outcome", "ok").timer())
        assertNotNull(meters.find("cloak.refusals").tags("code", "not_found").counter())
        val codes = CloakErrorCode.entries.map { it.code }.toSet() + "ok"
        val operations = OpenApiContract.specOperations.map { it.operationId }.toSet()
        for (meter in meters.meters.filter { it.id.name.startsWith("cloak.") }) {
            for (tag in meter.id.tags) {
                val allowed = when (tag.key) {
                    "operation" -> operations
                    "outcome", "code" -> codes
                    "kind" -> setOf("vault_created", "member_added", "member_role_set", "member_removed", "member_keys_replaced", "key_rotated")
                    else -> emptySet()
                }
                assertTrue(tag.value in allowed, "${meter.id.name} tag ${tag.key}=${tag.value}")
            }
        }
    }

    @Test
    fun `health is up with no detail while the schema is current`() {
        val result = assertNotNull(health.health())

        assertEquals(Status.UP, result.status)
        assertTrue(result.details.isEmpty())
    }

    /** Registers a new user over the API. */
    private fun registered(): TestClient =
        TestClient().also { assertEquals(201, api.call(POST, "/identity", it, CloakApi.registration(it)).status) }

    /** A log entry with every field at its longest. */
    private fun longestEntry(kind: String): Map<String, Any> =
        mapOf(
            "seq" to Long.MAX_VALUE, "kind" to kind, "subjectUserId" to Uuid.random().toString(), "role" to "viewer",
            "keyVersion" to Int.MAX_VALUE, "subjectKeys" to b64(TestBlobs.random(32)), "subjectKeyVersion" to Int.MAX_VALUE,
            "keyCommitment" to b64(TestBlobs.random(32)), "checkpoint" to b64(TestBlobs.random(32)), "requestEnd" to false,
            "authorKeyVersion" to Int.MAX_VALUE, "signature" to b64(TestBlobs.blob(65)),
        )

    /** A guard that refuses callers whose host id starts with `limited-`, and records what it is asked. */
    class RecordingGuard : CloakRequestGuard {
        /** What the guard was asked. */
        val calls: MutableList<Pair<String, String>> = Collections.synchronizedList(mutableListOf())

        override fun check(principal: String, operationId: String): Duration? {
            calls += principal to operationId
            return if (principal.startsWith("limited-")) Duration.ofMillis(1_500) else null
        }
    }

    /** The test host's guard and meter registry. */
    @Configuration(proxyBeanMethods = false)
    class GuardedHost {
        @Bean
        fun guard(): RecordingGuard = RecordingGuard()

        @Bean
        fun meterRegistry(): MeterRegistry = SimpleMeterRegistry()
    }
}
