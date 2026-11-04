package dev.voir.cloak.server.observability

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import org.slf4j.LoggerFactory

/**
 * Logs refused requests without letting a client flood the log or learn who is who from it.
 *
 * Refusals that suggest an attack or a broken client, such as a signature that does not verify or a
 * log entry that breaks a rule, are logged at WARN, at most [WARNINGS_PER_WINDOW] per code in every
 * [WINDOW_NANOS]; the next warning after a quiet stretch says how many were held back. Conflicts and
 * other expected refusals are logged at DEBUG. A line names the operation and the code only: never
 * a user id, a host user id, a key or a body. The detail, which may name a vault's position, is
 * logged at DEBUG only.
 */
internal object RefusalLog {
    /** Logger of refusals. */
    private val logger = LoggerFactory.getLogger("dev.voir.cloak.server.refusals")

    /** Codes that suggest an attack or a client bug. */
    private val SUSPICIOUS = setOf(CloakErrorCode.BAD_SIGNATURE, CloakErrorCode.LOG_REJECTED)

    /** Most warnings per code in one window. */
    private const val WARNINGS_PER_WINDOW = 10

    /** Length of a window: one minute. */
    private const val WINDOW_NANOS = 60_000_000_000L

    /** Warnings of the current window, by code. */
    private val windows = HashMap<CloakErrorCode, Window>()

    /**
     * Logs one refusal.
     *
     * @param operation The API's `operationId`.
     * @param refusal What the operation answered.
     */
    fun refused(operation: String, refusal: CloakException) {
        if (refusal.code in SUSPICIOUS) {
            val heldBack = admit(refusal.code, System.nanoTime()) ?: return
            if (heldBack > 0) {
                logger.warn("Cloak refused {}: {} ({} similar refusals held back)", operation, refusal.code.code, heldBack)
            } else {
                logger.warn("Cloak refused {}: {}", operation, refusal.code.code)
            }
        }
        if (logger.isDebugEnabled) logger.debug("Cloak refused {}: {}: {}", operation, refusal.code.code, refusal.detail)
    }

    /**
     * Decides whether a warning for [code] may be logged now.
     *
     * @return The number of warnings held back since the last one logged, or `null` to hold this one back.
     */
    @Synchronized
    private fun admit(code: CloakErrorCode, now: Long): Int? {
        val window = windows.getOrPut(code) { Window(now) }
        if (now - window.start >= WINDOW_NANOS) {
            window.start = now
            window.logged = 0
        }
        if (window.logged >= WARNINGS_PER_WINDOW) {
            window.heldBack += 1
            return null
        }
        window.logged += 1
        return window.heldBack.also { window.heldBack = 0 }
    }

    /**
     * Warnings of one code in the current window.
     *
     * @property start When the window began, in [System.nanoTime] units.
     * @property logged Warnings logged in it.
     * @property heldBack Warnings held back since the last one logged.
     */
    private class Window(
        var start: Long,
        var logged: Int = 0,
        var heldBack: Int = 0,
    )
}
