package dev.voir.cloak.spring.guard

import java.time.Duration

/**
 * Lets the host limit how often its users call Cloak, such as with a rate limiter it already runs.
 * Declare one as a bean; without one, Cloak limits nothing. Implementable from Java.
 *
 * It is asked once per request, after the caller is resolved and before the request body is read,
 * and sees only who calls which operation: never the body.
 */
public fun interface CloakRequestGuard {
    /**
     * Decides whether a request may go on.
     *
     * @param principal The host's id of the caller, as its [dev.voir.cloak.spring.auth.CloakPrincipalResolver] gave it.
     * @param operationId The API operation asked for, such as `writeSection` or `rotateVault`.
     * @return `null` to let the request through, or how long the caller should wait before trying
     *   again, which refuses it with `429 rate_limited` and a `Retry-After` of at least one second.
     */
    public fun check(principal: String, operationId: String): Duration?
}
