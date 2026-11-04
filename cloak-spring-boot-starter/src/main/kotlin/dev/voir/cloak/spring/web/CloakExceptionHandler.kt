package dev.voir.cloak.spring.web

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.spring.web.mapping.Wire
import dev.voir.cloak.api.models.FieldError
import dev.voir.cloak.api.models.Problem
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.ErrorResponse
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import tools.jackson.core.JacksonException

/**
 * Renders every failure of the Cloak controllers as an RFC 9457 problem with a stable code.
 * Only Cloak's own controllers are covered; the host's error handling is untouched.
 */
@RestControllerAdvice(basePackageClasses = [CloakExceptionHandler::class])
internal class CloakExceptionHandler {
    /** Logger of unexpected failures. */
    private val logger = LoggerFactory.getLogger(CloakExceptionHandler::class.java)

    /** Expected failures of Cloak operations; `busy` and `rate_limited` say when to retry. */
    @ExceptionHandler(CloakException::class)
    fun cloak(failure: CloakException, request: HttpServletRequest): ResponseEntity<Problem> =
        problem(
            code = failure.code,
            detail = failure.detail,
            request = request,
            currentVersion = failure.currentVersion,
            role = failure.role,
            errors = failure.fieldErrors.map { FieldError(it.pointer, it.code, it.message) },
            retryAfterSeconds = failure.retryAfterSeconds,
            vaultId = failure.vaultId?.let { Wire.uuid(it.value) },
        )

    /**
     * A body that is not JSON or does not fit the request schema, or that ran past the request size
     * limit while it was read (`payload_too_large`).
     */
    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun unreadable(failure: HttpMessageNotReadableException, request: HttpServletRequest): ResponseEntity<Problem> {
        if (generateSequence<Throwable>(failure) { it.cause }.any { it is RequestTooLargeException }) {
            return problem(CloakErrorCode.PAYLOAD_TOO_LARGE, RequestTooLargeException.DETAIL, request)
        }
        val pointer = (failure.cause as? JacksonException)?.path.orEmpty().joinToString("") { reference ->
            "/" + (reference.propertyName ?: reference.index.toString())
        }
        return problem(
            code = CloakErrorCode.VALIDATION_FAILED,
            detail = "The request body does not match the schema.",
            request = request,
            errors = listOf(FieldError(pointer, "schema", "Missing, null or of the wrong type.")),
        )
    }

    /**
     * Anything else. Framework rejections of a malformed request, such as a missing body or an
     * unsupported media type, become `validation_failed`; the rest is logged with a trace id and
     * never shown to the client.
     */
    @ExceptionHandler(Exception::class)
    fun unexpected(failure: Exception, request: HttpServletRequest): ResponseEntity<Problem> {
        if (generateSequence<Throwable>(failure) { it.cause }.any { it is RequestTooLargeException }) {
            return problem(CloakErrorCode.PAYLOAD_TOO_LARGE, RequestTooLargeException.DETAIL, request)
        }
        if (failure is ErrorResponse && failure.statusCode.is4xxClientError) {
            return problem(
                CloakErrorCode.VALIDATION_FAILED,
                failure.body.detail ?: "The request is malformed.",
                request,
            )
        }
        val traceId = Problems.traceId()
        logger.error("Cloak request {} {} failed [traceId={}]", request.method, request.requestURI, traceId, failure)
        return problem(CloakErrorCode.INTERNAL_ERROR, "Unexpected failure.", request, traceId = traceId)
    }

    /** Builds the problem response. */
    private fun problem(
        code: CloakErrorCode,
        detail: String,
        request: HttpServletRequest,
        currentVersion: Long? = null,
        role: Role? = null,
        errors: List<FieldError> = emptyList(),
        traceId: String = Problems.traceId(),
        retryAfterSeconds: Int? = null,
        vaultId: java.util.UUID? = null,
    ): ResponseEntity<Problem> {
        val response = ResponseEntity.status(code.status).contentType(MediaType.APPLICATION_PROBLEM_JSON)
        retryAfterSeconds?.let { response.header(HttpHeaders.RETRY_AFTER, it.toString()) }
        return response.body(Problems.of(code, detail, request.requestURI, currentVersion, role, errors, traceId, vaultId))
    }
}
