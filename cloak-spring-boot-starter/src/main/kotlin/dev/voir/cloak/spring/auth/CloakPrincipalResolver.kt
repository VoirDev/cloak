package dev.voir.cloak.spring.auth

import jakarta.servlet.http.HttpServletRequest

/**
 * Tells Cloak who the authenticated caller is. The host implements it on top of its own
 * authentication, for example by reading the Spring Security principal; Cloak never sees
 * credentials. Implementable from Java.
 *
 * Cloak still authorizes every resource itself: a resolved user sees only the vaults they are a
 * member of.
 */
public fun interface CloakPrincipalResolver {
    /**
     * Resolves the caller of [request].
     *
     * @param request Current request.
     * @return The host's id of the user, as its authentication gives it: any string of 1 to 255
     *   bytes in UTF-8 (`PROTOCOL.md` §5.0), from which Cloak derives its user id; or `null` when
     *   the request has no valid session (answered `401`).
     */
    public fun resolve(request: HttpServletRequest): String?
}
