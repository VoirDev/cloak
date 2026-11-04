package dev.voir.cloak.server.persistence

import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.observability.CloakEvents
import dev.voir.cloak.server.observability.RefusalLog
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.slf4j.LoggerFactory
import java.sql.SQLException
import java.time.Duration

/**
 * What every operation needs: the host's database, its clock and the server's settings.
 *
 * Every public operation runs through [operation], which times it, logs a refusal and reports its
 * events after it ended. Its transactions run through [OperationScope.asCaller], which refuses a
 * deleted caller (`PROTOCOL.md` §5.7) in that one place, or [OperationScope.withoutCaller] for the
 * few operations no registered user makes.
 *
 * @property database Exposed handle on the host's data source; never the global default.
 * @property clock Clock at database precision.
 * @property settings Timeouts, limits and the event listener.
 */
internal class CloakContext(
    private val database: Database,
    val clock: CloakClock,
    val settings: CloakSettings,
) {
    /**
     * Runs one operation of the API.
     *
     * @param name The API's `operationId`.
     * @param block Operation body; it opens its transaction through the scope.
     * @return The block's result.
     */
    fun <T> operation(name: String, block: OperationScope.() -> T): T {
        val scope = OperationScope(name)
        val start = System.nanoTime()
        var outcome = CloakEvents.OUTCOME_OK
        try {
            return scope.block()
        } catch (refusal: CloakException) {
            outcome = refusal.code.code
            RefusalLog.refused(name, refusal)
            throw refusal
        } catch (failure: Throwable) {
            outcome = CloakErrorCode.INTERNAL_ERROR.code
            throw failure
        } finally {
            val duration = Duration.ofNanos(System.nanoTime() - start)
            scope.committed.forEach { event -> deliver { event(it) } }
            if (outcome == CloakErrorCode.CHECKPOINT_CONFLICT.code) deliver { it.checkpointConflict(name) }
            deliver { it.operationCompleted(name, outcome, duration) }
        }
    }

    /**
     * Runs a short read outside any operation, such as an adapter's check of its caller; it reports
     * no events.
     *
     * @param block Transaction body.
     * @return The block's result.
     * @throws CloakException `busy` when the database ran out of time.
     */
    fun <T> unrecorded(block: () -> T): T = timed(settings.statementTimeout, block)

    /** Runs one transaction under the statement and lock timeouts, mapping running out of time to `busy`. */
    private fun <T> timed(statementTimeout: Duration, block: () -> T): T =
        try {
            transaction(database) {
                // Both settings are integers this server chose, never input.
                exec("set local statement_timeout = ${statementTimeout.toMillis()}")
                exec("set local lock_timeout = ${settings.lockTimeout.toMillis()}")
                block()
            }
        } catch (failure: SQLException) {
            throw busyOrNull(failure) ?: failure
        }

    /** Reports one event; a failing listener is logged, never the request's failure. */
    private fun deliver(event: (CloakEvents) -> Unit) {
        try {
            event(settings.events)
        } catch (failure: Exception) {
            logger.warn("A Cloak event listener failed", failure)
        }
    }

    /** Statement budget of a transaction. */
    enum class Budget {
        /** [CloakSettings.statementTimeout]. */
        STANDARD,

        /** [CloakSettings.checkpointStatementTimeout], for operations whose statements grow with the vault. */
        CHECKPOINT,
    }

    /**
     * One operation in progress: its transactions and the events they record.
     *
     * @property name The API's `operationId`.
     */
    inner class OperationScope(
        val name: String,
    ) : EventRecorder {
        /** Events of the transaction in progress; reported only if it commits. */
        private val pending = mutableListOf<(CloakEvents) -> Unit>()

        /** Events of committed transactions, reported once the operation ended. */
        internal val committed = mutableListOf<(CloakEvents) -> Unit>()

        /** Records an event, reported after the transaction commits. */
        override fun record(event: (CloakEvents) -> Unit) {
            pending += event
        }

        /**
         * Runs a transaction on behalf of a registered user: refuses them first when they are
         * deleted, holding a key-share lock on their identity row so an erasure cannot commit
         * while the request runs.
         *
         * @param caller The user making the request.
         * @param budget Statement budget.
         * @param block Transaction body; a thrown exception rolls everything back.
         * @return The block's result.
         * @throws CloakException `identity_deleted` when the caller is deleted, `busy` when the
         *   database ran out of time.
         */
        fun <T> asCaller(caller: UserId, budget: Budget = Budget.STANDARD, block: () -> T): T =
            run(budget) {
                if (IdentityRepository.isDeleted(caller, lock = true)) throw CloakException.identityDeleted()
                block()
            }

        /**
         * Runs a transaction no registered user makes: a registration, which checks the new user
         * itself, or the host's own erasure of a user.
         *
         * @param budget Statement budget.
         * @param block Transaction body.
         * @return The block's result.
         * @throws CloakException `busy` when the database ran out of time.
         */
        fun <T> withoutCaller(budget: Budget = Budget.STANDARD, block: () -> T): T = run(budget, block)

        /** Runs one transaction with its timeouts, and keeps its events if it commits. */
        private fun <T> run(budget: Budget, block: () -> T): T {
            pending.clear()
            val statementTimeout = when (budget) {
                Budget.STANDARD -> settings.statementTimeout
                Budget.CHECKPOINT -> settings.checkpointStatementTimeout
            }
            val result = try {
                timed(statementTimeout, block)
            } catch (failure: Throwable) {
                pending.clear()
                throw failure
            }
            committed += pending
            pending.clear()
            return result
        }
    }

    /** Logging and SQL state mapping. */
    private companion object {
        /** Logger of listener failures. */
        val logger = LoggerFactory.getLogger(CloakContext::class.java)

        /** SQL states of a statement cancelled by `statement_timeout`. */
        const val QUERY_CANCELED = "57014"

        /** SQL state of a lock not had within `lock_timeout`. */
        const val LOCK_NOT_AVAILABLE = "55P03"

        /** SQL state of a deadlock PostgreSQL broke by aborting this transaction. */
        const val DEADLOCK_DETECTED = "40P01"

        /** Seconds to wait after a statement ran out of time: the database is loaded. */
        const val RETRY_AFTER_TIMEOUT_SECONDS = 5

        /** Seconds to wait after a lock was not had: another request held the vault. */
        const val RETRY_AFTER_LOCK_SECONDS = 1

        /** A `busy` refusal for a timed-out, lock-starved or deadlocked statement, else `null`. */
        fun busyOrNull(failure: SQLException): CloakException? {
            val state = generateSequence<Throwable>(failure) { it.cause }
                .filterIsInstance<SQLException>()
                .firstNotNullOfOrNull { it.sqlState }
            return when (state) {
                QUERY_CANCELED -> CloakException.busy(RETRY_AFTER_TIMEOUT_SECONDS)
                LOCK_NOT_AVAILABLE, DEADLOCK_DETECTED -> CloakException.busy(RETRY_AFTER_LOCK_SECONDS)
                else -> null
            }
        }
    }
}

/**
 * Where code inside a transaction records events, reported after the transaction commits.
 */
internal fun interface EventRecorder {
    /**
     * Records an event.
     *
     * @param event Call on the listener.
     */
    fun record(event: (CloakEvents) -> Unit)
}
