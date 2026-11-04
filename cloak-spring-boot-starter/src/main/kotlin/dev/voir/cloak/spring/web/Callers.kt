package dev.voir.cloak.spring.web

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.spring.auth.CloakPrincipalResolver
import jakarta.servlet.http.HttpServletRequest

/**
 * Resolves who makes a request: always a user the host authenticated. Cloak has no guests. The
 * resolution is kept on the request, so the host's resolver runs once per request.
 *
 * @property resolver Host's principal resolver.
 */
internal class Callers(
    private val resolver: CloakPrincipalResolver,
) {
    /**
     * Returns the authenticated user's Cloak id.
     *
     * @param request Current request.
     * @return The user id derived from the host's id.
     * @throws CloakException `unauthenticated` without a valid host session.
     * @throws IllegalArgumentException when the resolver returns an invalid host user id, a host bug.
     */
    fun require(request: HttpServletRequest): UserId = requireHost(request).userId

    /**
     * Returns the authenticated user by the host's id.
     *
     * @param request Current request.
     * @return The host user id.
     * @throws CloakException `unauthenticated` without a valid host session.
     * @throws IllegalArgumentException when the resolver returns an invalid host user id, a host bug.
     */
    fun requireHost(request: HttpServletRequest): HostUserId =
        request.getAttribute(ATTRIBUTE) as? HostUserId
            ?: HostUserId.of(
                resolver.resolve(request)
                    ?: throw CloakException(CloakErrorCode.UNAUTHENTICATED, "Sign in to the application first."),
            ).also { request.setAttribute(ATTRIBUTE, it) }

    /** Request attribute names. */
    private companion object {
        /** Attribute holding the resolved caller. */
        val ATTRIBUTE: String = Callers::class.java.name + ".caller"
    }
}
