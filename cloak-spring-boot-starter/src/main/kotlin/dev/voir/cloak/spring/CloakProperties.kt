package dev.voir.cloak.spring

import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.meta.Limits
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.util.unit.DataSize
import java.time.Duration

/**
 * Settings under `cloak.*`.
 *
 * @property migrateOnStartup Whether to migrate the `cloak` schema when the application starts.
 * @property maxRequestSize Largest Cloak request body (`cloak.max-request-size`, 16MB by default);
 *   startup fails below 4MB, which the largest rotation needs. Larger bodies answer `413`.
 * @property database Database time limits of Cloak's transactions (`cloak.database.*`).
 * @property maxStoredSectionsPerVault Most sections one vault stores, deleted ones included
 *   (`cloak.max-stored-sections-per-vault`, 1 000 000 by default); never below the live limit of
 *   100 000. A deletion stays stored without content so the section's next write chains to it.
 * @property maxPendingInvitations Most vaults one user may be added to without accepting them
 *   (`cloak.max-pending-invitations`, 1 000 by default; at least 1). Adding one more answers
 *   `409 too_many_invitations`, unless the user accepted everything from the person adding them.
 * @property maxPendingInvitationsPerInviter Most of those one person may have added the user to
 *   (`cloak.max-pending-invitations-per-inviter`, 100 by default; at least 1), so one inviter cannot
 *   use up the whole limit; also `409 too_many_invitations`.
 * @property writePause Write pauses for checkpoints (`cloak.write-pause.*`).
 */
@ConfigurationProperties("cloak")
public data class CloakProperties(
    /** Migrate on startup. */
    public val migrateOnStartup: Boolean = true,
    /** Largest Cloak request body. */
    public val maxRequestSize: DataSize = DataSize.ofBytes(Limits.DEFAULT_MAX_REQUEST_BYTES.toLong()),
    /** Database time limits. */
    public val database: Database = Database(),
    /** Most stored sections of one vault. */
    public val maxStoredSectionsPerVault: Int = CloakSettings.DEFAULT_MAX_STORED_SECTIONS_PER_VAULT,
    /** Most vaults awaiting one user's acceptance. */
    public val maxPendingInvitations: Int = CloakSettings.DEFAULT_MAX_PENDING_INVITATIONS,
    /** Most vaults awaiting one user's acceptance from one inviter. */
    public val maxPendingInvitationsPerInviter: Int = CloakSettings.DEFAULT_MAX_PENDING_INVITATIONS_PER_INVITER,
    /** Write pauses. */
    public val writePause: WritePause = WritePause(),
) {
    /**
     * Write pauses (`PROTOCOL.md` §7.5): a member about to send a checkpoint pauses section writes
     * so they cannot outrun it. A write refused by a pause answers `503 busy` with a `Retry-After`
     * of at most 2 seconds, since the pause usually ends as soon as the checkpoint is applied.
     *
     * @property duration How long a pause holds a vault at most, in whole seconds.
     * @property interval Least time between two pauses of one vault by the same member who is not
     *   an admin, renewals included, in whole seconds.
     */
    public data class WritePause(
        /** How long a pause holds. */
        public val duration: Duration = CloakSettings.DEFAULT_WRITE_PAUSE,
        /** Least time between two pauses by the same non-admin. */
        public val interval: Duration = CloakSettings.DEFAULT_WRITE_PAUSE_INTERVAL,
    )

    /**
     * Database time limits, set per Cloak transaction (`SET LOCAL`), never on the host's own work.
     *
     * @property statementTimeout Most time one statement of an ordinary operation may take.
     * @property checkpointStatementTimeout Most time one statement of an operation that builds or
     *   reads a checkpoint may take; its statements grow with the vault.
     * @property lockTimeout Most time a statement waits for a lock, such as a vault another
     *   request is changing. Running out of time answers `503 busy` with `Retry-After`.
     */
    public data class Database(
        /** Most time per ordinary statement. */
        public val statementTimeout: Duration = CloakSettings.DEFAULT_STATEMENT_TIMEOUT,
        /** Most time per checkpoint statement. */
        public val checkpointStatementTimeout: Duration = CloakSettings.DEFAULT_CHECKPOINT_STATEMENT_TIMEOUT,
        /** Most time waiting for a lock. */
        public val lockTimeout: Duration = CloakSettings.DEFAULT_LOCK_TIMEOUT,
    )
}
