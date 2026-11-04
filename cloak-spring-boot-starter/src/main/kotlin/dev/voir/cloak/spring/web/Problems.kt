package dev.voir.cloak.spring.web

import dev.voir.cloak.api.models.ErrorCode
import dev.voir.cloak.api.models.FieldError
import dev.voir.cloak.api.models.Problem
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.spring.web.mapping.Wire
import org.slf4j.MDC
import java.net.URI
import java.util.UUID

/** Builds the RFC 9457 problems every Cloak failure is answered with, in and outside Spring MVC. */
internal object Problems {
    /**
     * Builds a problem.
     *
     * @param code Stable error code.
     * @param detail Explanation of this occurrence; never secrets.
     * @param instance Path of the failing request.
     * @param currentVersion Current version for the version-conflict codes.
     * @param role Role the caller needs, for `role_required`.
     * @param errors Field errors, for `validation_failed`.
     * @param traceId Correlation id for the server logs.
     * @param vaultId The vault a batch request was refused for.
     * @return The problem.
     */
    fun of(
        code: CloakErrorCode,
        detail: String,
        instance: String,
        currentVersion: Long? = null,
        role: Role? = null,
        errors: List<FieldError> = emptyList(),
        traceId: String = traceId(),
        vaultId: java.util.UUID? = null,
    ): Problem =
        Problem(
            type = URI("urn:cloak:problem:${code.code}"),
            title = code.title,
            status = code.status,
            detail = detail,
            instance = instance,
            code = checkNotNull(ErrorCode.fromValue(code.code)) { "Code ${code.code} is missing from the spec" },
            traceId = traceId,
            currentVersion = currentVersion,
            role = role?.let(Wire::role),
            errors = errors.ifEmpty { null },
            vaultId = vaultId,
        )

    /**
     * Returns the tracing system's trace id when there is one, else a fresh random id.
     *
     * @return The trace id.
     */
    fun traceId(): String = MDC.get("traceId") ?: UUID.randomUUID().toString().replace("-", "")
}
