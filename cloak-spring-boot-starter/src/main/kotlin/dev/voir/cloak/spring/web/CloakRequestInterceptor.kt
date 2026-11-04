package dev.voir.cloak.spring.web

import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.spring.guard.CloakRequestGuard
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.HandlerInterceptor
import java.time.Duration

/**
 * Admits every Cloak request in one place, before its body is read: resolves the caller
 * (`401 unauthenticated` without a session), asks the host's [CloakRequestGuard] (`429
 * rate_limited`), and refuses a deleted caller (`410 identity_deleted`, `PROTOCOL.md` §5.7), so a
 * deleted user's every request answers the same. Operations check deletion again inside their
 * transaction, which is what counts.
 *
 * Only `getMeta` needs no session.
 *
 * @property cloak Cloak operations.
 * @property callers Caller resolution.
 * @property guard The host's request guard, if any.
 */
internal class CloakRequestInterceptor(
    private val cloak: CloakServer,
    private val callers: Callers,
    private val guard: CloakRequestGuard?,
) : HandlerInterceptor {
    /** Admits or refuses the request. */
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        val operation = (handler as? HandlerMethod)?.getMethodAnnotation(CloakOperation::class.java)?.value ?: return true
        if (operation == PUBLIC_OPERATION) return true
        val caller = callers.requireHost(request)
        guard?.check(caller.value, operation)?.let { wait ->
            throw CloakException(CloakErrorCode.RATE_LIMITED, "Too many requests; retry later.", retryAfterSeconds = seconds(wait))
        }
        cloak.identity.requireNotDeleted(caller.userId)
        return true
    }

    /** Operations without a session, and rounding. */
    private companion object {
        /** `GET /meta`. */
        const val PUBLIC_OPERATION = "getMeta"

        /** A wait in whole seconds, rounded up, at least one. */
        fun seconds(wait: Duration): Int {
            val millis = wait.toMillis().coerceAtLeast(1)
            return ((millis + 999) / 1_000).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        }
    }
}
