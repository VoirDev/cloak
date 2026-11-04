package dev.voir.cloak.spring

import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.section.domain.SectionWriteInput
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.spring.testhost.CloakTestApplication
import kotlinx.io.bytestring.ByteString
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import kotlin.io.encoding.Base64

/**
 * Calls the starter through MockMvc like an HTTP client would, and checks every response
 * against the OpenAPI contract before returning it.
 */
class CloakApi(
    private val mvc: MockMvc,
    private val mapper: JsonMapper,
) {
    /**
     * A response.
     *
     * @property status HTTP status.
     * @property body Parsed JSON body, or `null` when empty.
     * @property headers Response headers.
     */
    data class Response(val status: Int, val body: JsonNode?, val headers: Map<String, String>) {
        /** Field of the body. */
        operator fun get(field: String): JsonNode = checkNotNull(body)[field]

        /** The problem code, for an error response. */
        val code: String get() = this["code"].asString()
    }

    /** Sends one request; [path] is relative to `/cloak/v1` and may carry a query. */
    fun call(method: HttpMethod, path: String, user: TestClient? = null, body: Any? = null): Response {
        val request = MockMvcRequestBuilders.request(method, "/cloak/v1$path")
        user?.let { request.header(CloakTestApplication.USER_HEADER, it.hostUserId.value) }
        body?.let { request.contentType(MediaType.APPLICATION_JSON).content(if (it is String) it else mapper.writeValueAsString(it)) }
        val result = mvc.perform(request).andReturn().response
        val text = result.contentAsString
        OpenApiContract.check(method.name(), path.substringBefore('?'), result.status, result.contentType, text)
        return Response(
            status = result.status,
            body = text.takeIf { it.isNotEmpty() }?.let(mapper::readTree),
            headers = result.headerNames.associateWith { result.getHeader(it).orEmpty() },
        )
    }

    /** Wire forms of what [TestClient] builds. */
    companion object {
        private val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        fun b64(value: ByteString): String = base64.encode(value.toByteArray())

        fun bytes(value: String): ByteString = ByteString(base64.decode(value))

        fun kdf(kdf: KdfParams): Map<String, Any> =
            mapOf("algorithm" to "argon2id", "salt" to b64(kdf.salt), "memoryKib" to kdf.memoryKib, "iterations" to kdf.iterations, "parallelism" to kdf.parallelism)

        fun registration(client: TestClient): Map<String, Any> =
            client.registration().let {
                mapOf(
                    "cryptoSuite" to it.cryptoSuite,
                    "encryptionPublicKey" to b64(it.encryptionPublicKey),
                    "signingPublicKey" to b64(it.signingPublicKey),
                    "recoverySigningPublicKey" to b64(it.recoverySigningPublicKey),
                    "signature" to b64(it.signature),
                    "kdf" to kdf(it.kdf),
                    "privateKeyBundle" to b64(it.privateKeyBundle),
                    "recoveryKeyBundle" to b64(it.recoveryKeyBundle),
                )
            }

        fun replacement(client: TestClient): Map<String, Any> =
            client.replacement().let {
                mapOf(
                    "expectedKeyVersion" to it.expectedKeyVersion,
                    "encryptionPublicKey" to b64(it.encryptionPublicKey),
                    "signingPublicKey" to b64(it.signingPublicKey),
                    "recoverySigningPublicKey" to b64(it.recoverySigningPublicKey),
                    "signature" to b64(it.signature),
                    "recoverySignature" to b64(it.recoverySignature),
                    "kdf" to kdf(it.kdf),
                    "privateKeyBundle" to b64(it.privateKeyBundle),
                    "recoveryKeyBundle" to b64(it.recoveryKeyBundle),
                )
            }

        fun log(entry: LogEntryInput): Map<String, Any> =
            buildMap {
                put("seq", entry.seq)
                put("kind", entry.kind.code)
                entry.subjectUserId?.let { put("subjectUserId", it.value.toString()) }
                entry.role?.let { put("role", it.code) }
                put("keyVersion", entry.keyVersion)
                entry.subjectKeys?.let { put("subjectKeys", b64(it)) }
                entry.subjectKeyVersion?.let { put("subjectKeyVersion", it) }
                entry.keyCommitment?.let { put("keyCommitment", b64(it)) }
                entry.checkpoint?.let { put("checkpoint", b64(it)) }
                put("requestEnd", entry.requestEnd)
                put("authorKeyVersion", entry.authorKeyVersion)
                entry.nodeId?.let { put("nodeId", it.value.toString()) }
                entry.homeVaultId?.let { put("homeVaultId", it.value.toString()) }
                entry.nodeKey?.let { put("nodeKey", it) }
                entry.sections?.let { put("sections", it) }
                put("signature", b64(entry.signature))
            }

        fun write(input: SectionWriteInput): Map<String, Any> =
            buildMap {
                put("nodeType", input.nodeType.value)
                put("homeVaultId", input.homeVaultId.value.toString())
                put("ownerUserId", input.ownerUserId.value.toString())
                put("nodeKey", input.nodeKey)
                put("vaultKeyVersion", input.vaultKeyVersion)
                put("dataVersion", input.dataVersion)
                put("deleted", input.deleted)
                put("logSeq", input.logSeq)
                put("logHeadHash", b64(input.logHeadHash))
                input.previousWriteHash?.let { put("previousWriteHash", b64(it)) }
                put("writerKeyVersion", input.writerKeyVersion)
                input.ciphertext?.let { put("ciphertext", b64(it)) }
                put("signature", b64(input.signature))
            }
    }
}
