package dev.voir.cloak.server

import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.observability.CloakEvents
import java.time.Duration

/**
 * How a [CloakServer] protects the host's database and reports its work. Build one with
 * [builder]; every setting has a default.
 *
 * Database time is bounded per statement: PostgreSQL's `statement_timeout` and `lock_timeout` are
 * set at the start of every Cloak transaction (`SET LOCAL`), so they never touch the host's own
 * work. A statement that runs out of time, or a lock that cannot be had in time, rolls the request
 * back and answers `busy` with a time to retry after.
 *
 * @property maxRequestBytes Largest request body an adapter accepts, published by `GET /meta`;
 *   never below [Limits.MIN_REQUEST_BYTES], so the largest rotation always fits.
 * @property statementTimeout Most time one statement of an ordinary operation may take.
 * @property checkpointStatementTimeout Most time one statement of an operation that builds or
 *   reads a checkpoint may take: role changes, departures, rotations, key replacements, erasure and
 *   checkpoint reads, whose statements grow with the vault.
 * @property lockTimeout Most time a statement waits for a lock, such as a vault another request
 *   is changing.
 * @property maxStoredSectionsPerVault Most sections one vault stores, deletions included: a deletion
 *   is kept without content so the section's next write chains to it (`PROTOCOL.md` §7.5). Bounds
 *   the database; never below [Limits.MAX_SECTIONS_PER_VAULT].
 * @property writePause How long a write pause holds a vault (`PROTOCOL.md` §7.5).
 * @property writePauseInterval Least time between two pauses of one vault by the same member who is
 *   not an admin, renewals included, so no member can keep a vault paused.
 * @property maxPendingInvitations Most vaults a user may be added to without accepting them
 *   (`PROTOCOL.md` §12.4); adding one more answers `too_many_invitations`.
 * @property maxPendingInvitationsPerInviter Most of those one person may have added the user to,
 *   so one inviter cannot use up the whole limit; adding one more answers `too_many_invitations`.
 * @property events Listener of the server's events.
 */
public class CloakSettings private constructor(
    /** Largest request body. */
    public val maxRequestBytes: Int,
    /** Most time one statement of an ordinary operation may take. */
    public val statementTimeout: Duration,
    /** Most time one statement of a checkpoint operation may take. */
    public val checkpointStatementTimeout: Duration,
    /** Most time a statement waits for a lock. */
    public val lockTimeout: Duration,
    /** Most sections one vault stores, deletions included. */
    public val maxStoredSectionsPerVault: Int,
    /** How long a write pause holds a vault. */
    public val writePause: Duration,
    /** Least time between two pauses of one vault by the same member who is not an admin. */
    public val writePauseInterval: Duration,
    /** Most vaults a user may be added to without accepting them. */
    public val maxPendingInvitations: Int,
    /** Most vaults one person may have added a user to without the user accepting them. */
    public val maxPendingInvitationsPerInviter: Int,
    /** Listener of the server's events. */
    public val events: CloakEvents,
) {
    /**
     * Returns a builder holding these settings.
     *
     * @return A builder to change some of them.
     */
    public fun toBuilder(): Builder =
        Builder()
            .maxRequestBytes(maxRequestBytes)
            .statementTimeout(statementTimeout)
            .checkpointStatementTimeout(checkpointStatementTimeout)
            .lockTimeout(lockTimeout)
            .maxStoredSectionsPerVault(maxStoredSectionsPerVault)
            .writePause(writePause)
            .writePauseInterval(writePauseInterval)
            .maxPendingInvitations(maxPendingInvitations)
            .maxPendingInvitationsPerInviter(maxPendingInvitationsPerInviter)
            .events(events)

    /**
     * Collects settings; [build] checks them.
     */
    public class Builder internal constructor() {
        /** See [CloakSettings.maxRequestBytes]. */
        private var maxRequestBytes: Int = Limits.DEFAULT_MAX_REQUEST_BYTES

        /** See [CloakSettings.statementTimeout]. */
        private var statementTimeout: Duration = DEFAULT_STATEMENT_TIMEOUT

        /** See [CloakSettings.checkpointStatementTimeout]. */
        private var checkpointStatementTimeout: Duration = DEFAULT_CHECKPOINT_STATEMENT_TIMEOUT

        /** See [CloakSettings.lockTimeout]. */
        private var lockTimeout: Duration = DEFAULT_LOCK_TIMEOUT

        /** See [CloakSettings.maxStoredSectionsPerVault]. */
        private var maxStoredSectionsPerVault: Int = DEFAULT_MAX_STORED_SECTIONS_PER_VAULT

        /** See [CloakSettings.writePause]. */
        private var writePause: Duration = DEFAULT_WRITE_PAUSE

        /** See [CloakSettings.writePauseInterval]. */
        private var writePauseInterval: Duration = DEFAULT_WRITE_PAUSE_INTERVAL

        /** See [CloakSettings.maxPendingInvitations]. */
        private var maxPendingInvitations: Int = DEFAULT_MAX_PENDING_INVITATIONS

        /** See [CloakSettings.maxPendingInvitationsPerInviter]. */
        private var maxPendingInvitationsPerInviter: Int = DEFAULT_MAX_PENDING_INVITATIONS_PER_INVITER

        /** See [CloakSettings.events]. */
        private var events: CloakEvents = CloakEvents.NONE

        /**
         * Sets [CloakSettings.maxRequestBytes].
         *
         * @param bytes Largest request body.
         * @return This builder.
         */
        public fun maxRequestBytes(bytes: Int): Builder = apply { maxRequestBytes = bytes }

        /**
         * Sets [CloakSettings.statementTimeout].
         *
         * @param timeout Most time per statement.
         * @return This builder.
         */
        public fun statementTimeout(timeout: Duration): Builder = apply { statementTimeout = timeout }

        /**
         * Sets [CloakSettings.checkpointStatementTimeout].
         *
         * @param timeout Most time per statement of a checkpoint operation.
         * @return This builder.
         */
        public fun checkpointStatementTimeout(timeout: Duration): Builder = apply { checkpointStatementTimeout = timeout }

        /**
         * Sets [CloakSettings.lockTimeout].
         *
         * @param timeout Most time a statement waits for a lock.
         * @return This builder.
         */
        public fun lockTimeout(timeout: Duration): Builder = apply { lockTimeout = timeout }

        /**
         * Sets [CloakSettings.maxStoredSectionsPerVault].
         *
         * @param sections Most stored sections of one vault.
         * @return This builder.
         */
        public fun maxStoredSectionsPerVault(sections: Int): Builder = apply { maxStoredSectionsPerVault = sections }

        /**
         * Sets [CloakSettings.writePause].
         *
         * @param duration How long a write pause holds a vault.
         * @return This builder.
         */
        public fun writePause(duration: Duration): Builder = apply { writePause = duration }

        /**
         * Sets [CloakSettings.writePauseInterval].
         *
         * @param interval Least time between two pauses by the same member who is not an admin.
         * @return This builder.
         */
        public fun writePauseInterval(interval: Duration): Builder = apply { writePauseInterval = interval }

        /**
         * Sets [CloakSettings.maxPendingInvitations].
         *
         * @param invitations Most vaults a user may be added to without accepting them.
         * @return This builder.
         */
        public fun maxPendingInvitations(invitations: Int): Builder = apply { maxPendingInvitations = invitations }

        /**
         * Sets [CloakSettings.maxPendingInvitationsPerInviter].
         *
         * @param invitations Most vaults one person may have added a user to without the user accepting them.
         * @return This builder.
         */
        public fun maxPendingInvitationsPerInviter(invitations: Int): Builder = apply { maxPendingInvitationsPerInviter = invitations }

        /**
         * Sets [CloakSettings.events].
         *
         * @param listener Listener of the server's events.
         * @return This builder.
         */
        public fun events(listener: CloakEvents): Builder = apply { events = listener }

        /**
         * Checks and returns the settings.
         *
         * @return The settings.
         * @throws IllegalArgumentException when [maxRequestBytes] is below [Limits.MIN_REQUEST_BYTES],
         *   a timeout is not positive or is longer than a day, the checkpoint statement timeout is
         *   shorter than the ordinary one, the stored section limit is below the live one, or the
         *   write pause is not between 1 second and 10 minutes and its interval not at least as long,
         *   or the pending invitation limit is not positive.
         */
        public fun build(): CloakSettings {
            require(maxRequestBytes >= Limits.MIN_REQUEST_BYTES) {
                "Cloak's request size limit is $maxRequestBytes bytes, below ${Limits.MIN_REQUEST_BYTES}: the largest " +
                    "rotation would not fit, and access could not be taken away. Raise it."
            }
            for ((name, timeout) in listOf(
                "statement timeout" to statementTimeout,
                "checkpoint statement timeout" to checkpointStatementTimeout,
                "lock timeout" to lockTimeout,
            )) {
                require(!timeout.isNegative && !timeout.isZero && timeout <= MAX_TIMEOUT) {
                    "Cloak's $name must be positive and at most a day, not $timeout."
                }
            }
            require(checkpointStatementTimeout >= statementTimeout) {
                "Cloak's checkpoint statement timeout must not be shorter than its statement timeout."
            }
            require(maxStoredSectionsPerVault >= Limits.MAX_SECTIONS_PER_VAULT) {
                "Cloak's stored section limit must be at least the live limit, ${Limits.MAX_SECTIONS_PER_VAULT}."
            }
            require(writePause >= Duration.ofSeconds(1) && writePause <= MAX_WRITE_PAUSE && writePause.toNanos() % 1_000_000_000L == 0L) {
                "Cloak's write pause must be whole seconds between 1 second and $MAX_WRITE_PAUSE, not $writePause."
            }
            require(writePauseInterval >= writePause && writePauseInterval <= MAX_TIMEOUT && writePauseInterval.toNanos() % 1_000_000_000L == 0L) {
                "Cloak's write pause interval must be whole seconds, at least the pause and at most a day, not $writePauseInterval."
            }
            require(maxPendingInvitations >= 1) { "Cloak's pending invitation limit must be positive, not $maxPendingInvitations." }
            require(maxPendingInvitationsPerInviter >= 1) {
                "Cloak's pending invitation limit per inviter must be positive, not $maxPendingInvitationsPerInviter."
            }
            return CloakSettings(
                maxRequestBytes,
                statementTimeout,
                checkpointStatementTimeout,
                lockTimeout,
                maxStoredSectionsPerVault,
                writePause,
                writePauseInterval,
                maxPendingInvitations,
                maxPendingInvitationsPerInviter,
                events,
            )
        }
    }

    /** Defaults and construction. */
    public companion object {
        /** Default [statementTimeout]. */
        @JvmField
        public val DEFAULT_STATEMENT_TIMEOUT: Duration = Duration.ofSeconds(5)

        /** Default [checkpointStatementTimeout]. */
        @JvmField
        public val DEFAULT_CHECKPOINT_STATEMENT_TIMEOUT: Duration = Duration.ofSeconds(60)

        /** Default [lockTimeout]. */
        @JvmField
        public val DEFAULT_LOCK_TIMEOUT: Duration = Duration.ofSeconds(5)

        /** Default [maxStoredSectionsPerVault]. */
        public const val DEFAULT_MAX_STORED_SECTIONS_PER_VAULT: Int = 1_000_000

        /** Default [writePause]. */
        @JvmField
        public val DEFAULT_WRITE_PAUSE: Duration = Duration.ofSeconds(30)

        /** Default [writePauseInterval]. */
        @JvmField
        public val DEFAULT_WRITE_PAUSE_INTERVAL: Duration = Duration.ofMinutes(5)

        /** Default [maxPendingInvitations]. */
        public const val DEFAULT_MAX_PENDING_INVITATIONS: Int = 1_000

        /** Default [maxPendingInvitationsPerInviter]. */
        public const val DEFAULT_MAX_PENDING_INVITATIONS_PER_INVITER: Int = 100

        /** Longest timeout accepted. */
        private val MAX_TIMEOUT: Duration = Duration.ofDays(1)

        /** Longest write pause accepted: long enough to send a checkpoint, short enough not to stall writers. */
        private val MAX_WRITE_PAUSE: Duration = Duration.ofMinutes(10)

        /**
         * Starts building settings from the defaults.
         *
         * @return A builder.
         */
        @JvmStatic
        public fun builder(): Builder = Builder()

        /**
         * Returns the default settings.
         *
         * @return Settings with every default.
         */
        @JvmStatic
        public fun defaults(): CloakSettings = Builder().build()
    }
}
