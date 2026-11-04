package dev.voir.cloak.spring.web.mapping

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.error.FieldError
import dev.voir.cloak.server.section.domain.NodeType
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import kotlinx.io.bytestring.ByteString
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid
import kotlin.uuid.toKotlinUuid
import dev.voir.cloak.api.models.LogEntryKind as ApiLogEntryKind
import dev.voir.cloak.api.models.Role as ApiRole

/**
 * Conversions between generated wire models and core values. Jackson already checked JSON
 * types, UUIDs and instants; what is left are strings whose format the core needs, and every
 * parse names the JSON Pointer of its value.
 */
internal object Wire {
    /** Base64url without padding, as the API requires. */
    private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

    /**
     * Decodes base64url without padding.
     *
     * @param value Wire value.
     * @param pointer JSON Pointer of the value.
     * @return The bytes.
     */
    fun bytes(value: String, pointer: String): ByteString =
        try {
            ByteString(BASE64.decode(value))
        } catch (_: IllegalArgumentException) {
            throw invalid(pointer, "format", "Must be base64url without padding.")
        }

    /**
     * Decodes an optional base64url value.
     *
     * @param value Wire value, or `null`.
     * @param pointer JSON Pointer of the value.
     * @return The bytes, or `null`.
     */
    fun optionalBytes(value: String?, pointer: String): ByteString? = value?.let { bytes(it, pointer) }

    /**
     * Encodes bytes as base64url without padding.
     *
     * @param value Bytes.
     * @return Wire value.
     */
    fun text(value: ByteString): String = BASE64.encode(value.toByteArray())

    /**
     * Parses a section name.
     *
     * @param value Wire value.
     * @param pointer JSON Pointer of the value.
     * @return The name.
     */
    fun sectionName(value: String, pointer: String): SectionName {
        if (!SectionName.PATTERN.matches(value)) throw invalid(pointer, "pattern", "Must match ${SectionName.PATTERN}.")
        return SectionName(value)
    }

    /**
     * Parses a node type.
     *
     * @param value Wire value.
     * @param pointer JSON Pointer of the value.
     * @return The type.
     */
    fun nodeType(value: String, pointer: String): NodeType {
        if (!NodeType.PATTERN.matches(value)) throw invalid(pointer, "pattern", "Must match ${NodeType.PATTERN}.")
        return NodeType(value)
    }

    /**
     * Parses a UUID from a path or query string.
     *
     * @param value Wire value.
     * @param pointer JSON Pointer of the value.
     * @return The UUID.
     */
    fun uuid(value: String, pointer: String): Uuid =
        runCatching { Uuid.parse(value) }.getOrElse { throw invalid(pointer, "format", "Must be a UUID.") }

    /** Converts a generated role; the enums share their wire values. */
    fun role(value: ApiRole): Role = Role.fromCode(value.value)

    /** Converts a core role. */
    fun role(value: Role): ApiRole = checkNotNull(ApiRole.fromValue(value.code)) { "Role ${value.code} is missing from the spec" }

    /** Converts a generated log entry kind. */
    fun kind(value: ApiLogEntryKind): LogEntryKind = LogEntryKind.fromCode(value.value)

    /** Converts a core log entry kind. */
    fun kind(value: LogEntryKind): ApiLogEntryKind =
        checkNotNull(ApiLogEntryKind.fromValue(value.code)) { "Kind ${value.code} is missing from the spec" }

    /** Converts a wire UUID. */
    fun uuid(value: UUID): Uuid = value.toKotlinUuid()

    /** Converts a core UUID. */
    fun uuid(value: Uuid): UUID = value.toJavaUuid()

    /** Converts a core instant. */
    fun instant(value: Instant): java.time.Instant = value.toJavaInstant()

    /**
     * A single-field `validation_failed` problem.
     *
     * @param pointer JSON Pointer of the value.
     * @param rule Violated rule.
     * @param message Explanation.
     * @return The exception to throw.
     */
    fun invalid(pointer: String, rule: String, message: String): CloakException =
        CloakException(
            code = CloakErrorCode.VALIDATION_FAILED,
            detail = "The request has 1 invalid field.",
            fieldErrors = listOf(FieldError(pointer, rule, message)),
        )
}
