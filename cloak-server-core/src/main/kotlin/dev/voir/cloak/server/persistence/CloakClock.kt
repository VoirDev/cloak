package dev.voir.cloak.server.persistence

import kotlin.time.Clock
import kotlin.time.Instant

/**
 * The host's clock, truncated to the microsecond precision PostgreSQL stores, so a value read
 * back equals the value written.
 *
 * @property clock Source of the current instant.
 */
internal class CloakClock(
    private val clock: Clock,
) {
    /**
     * Returns the current instant.
     *
     * @return Now, truncated to whole microseconds.
     */
    fun now(): Instant {
        val now = clock.now()
        return Instant.fromEpochSeconds(now.epochSeconds, now.nanosecondsOfSecond / 1_000 * 1_000)
    }
}
