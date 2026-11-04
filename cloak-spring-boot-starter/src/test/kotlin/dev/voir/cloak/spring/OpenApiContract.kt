package dev.voir.cloak.spring

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SchemaLocation
import com.networknt.schema.SpecVersion
import java.io.File
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The OpenAPI contract, used to check that every response the starter sends has a status the
 * spec lists for that operation and a body that matches its schema.
 */
object OpenApiContract {
    private const val DOCUMENT_URI = "https://cloak.test/openapi.json"
    private val json = ObjectMapper()
    private val document: JsonNode =
        ObjectMapper(YAMLFactory()).readTree(File(System.getProperty("cloak.openapi")))
    private val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012) { builder ->
        builder.schemaLoaders { it.schemas(mapOf(DOCUMENT_URI to json.writeValueAsString(document))) }
    }

    /** Path items as (path regex, path item), literal paths first, as Spring routes them. */
    private val operations = document["paths"].properties()
        .sortedBy { (template, _) -> template.count { it == '{' } }
        .map { (template, item) -> Regex("^" + template.replace(Regex("\\{[^}]+}"), "[^/]+") + "$") to item }

    /**
     * Fails unless [status] and [body] match what the spec declares for [method] [path].
     *
     * @param path Request path relative to `/cloak/v1`, without query.
     */
    fun check(method: String, path: String, status: Int, contentType: String?, body: String) {
        val item = operations.firstOrNull { it.first.matches(path) }?.second ?: fail("No spec path matches $path")
        val operation = item[method.lowercase()] ?: fail("The spec has no $method $path")
        var response = operation["responses"][status.toString()] ?: fail("The spec lists no $status for $method $path")
        response["\$ref"]?.let { response = resolve(it.asText()) }
        val content = response["content"]
        if (content == null) {
            assertTrue(body.isEmpty(), "$method $path $status must have no body")
            return
        }
        val media = content.properties().firstOrNull { contentType?.startsWith(it.key) == true }
            ?: fail("$method $path $status returned $contentType, the spec says ${content.properties().map { it.key }}")
        val schemaRef = media.value["schema"]["\$ref"]?.asText() ?: fail("Inline response schemas are not supported")
        val errors = factory.getSchema(SchemaLocation.of(DOCUMENT_URI + schemaRef)).validate(json.readTree(body))
        assertTrue(errors.isEmpty(), "$method $path $status does not match $schemaRef: $errors\n$body")
    }

    /** Every operation of the spec as (method, path template with unnamed variables). */
    val operationKeys: Set<Pair<String, String>> by lazy {
        document["paths"].properties().flatMap { (template, item) ->
            item.properties().map { it.key }
                .filter { it in setOf("get", "put", "post", "patch", "delete") }
                .map { it.uppercase() to normalize(template) }
        }.toSet()
    }

    /**
     * One operation of the spec.
     *
     * @property method HTTP method.
     * @property template Path template relative to `/cloak/v1`.
     * @property operationId The operation's `operationId`.
     * @property hasBody Whether it takes a request body.
     */
    data class Operation(val method: String, val template: String, val operationId: String, val hasBody: Boolean)

    /** Every operation of the spec. */
    val specOperations: List<Operation> by lazy {
        document["paths"].properties().flatMap { (template, item) ->
            item.properties().filter { it.key in setOf("get", "put", "post", "patch", "delete") }.map { (method, operation) ->
                Operation(method.uppercase(), template, operation["operationId"].asText(), operation.has("requestBody"))
            }
        }
    }

    /**
     * A path template with its variables unnamed, so templates that name them differently compare.
     *
     * @param template Path template relative to `/cloak/v1`.
     * @return The template with every `{name}` as `{}`.
     */
    fun normalize(template: String): String = template.replace(Regex("\\{[^}]+}"), "{}")

    private fun resolve(ref: String): JsonNode =
        ref.removePrefix("#/").split("/").fold(document) { node, key -> node[key] }
}
