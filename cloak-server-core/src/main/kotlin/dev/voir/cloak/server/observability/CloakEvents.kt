package dev.voir.cloak.server.observability

import java.time.Duration

/**
 * What the server reports about its work, for the host's metrics. Every method has a no-op default,
 * so a host implements only what it uses; Java hosts implement the interface directly.
 *
 * The server calls these only after the operation's transaction ended: events of a request that
 * rolled back are never reported, except its outcome. An exception thrown by a listener is logged
 * and never fails the request.
 *
 * Events carry no user ids, host user ids, vault ids, keys, ciphertext or request bodies: a Cloak
 * user id is a hash of the host's id, which a dictionary reverses.
 */
public interface CloakEvents {
    /**
     * An operation of the API ended.
     *
     * @param operation The API's `operationId`, such as `rotateVault`.
     * @param outcome [OUTCOME_OK], or the error code the operation answered with.
     * @param duration Time the operation took, validation included.
     */
    public fun operationCompleted(operation: String, outcome: String, duration: Duration) {}

    /**
     * A checkpoint did not match the stored latest writes, so its author must build it again; a
     * high rate means writes keep slipping in while checkpoints are built.
     *
     * @param operation The API's `operationId` that carried the checkpoint.
     */
    public fun checkpointConflict(operation: String) {}

    /**
     * A log entry was stored.
     *
     * @param kind The entry's kind, such as `member_added`.
     */
    public fun logEntryAppended(kind: String) {}

    /**
     * A checkpoint was stored.
     *
     * @param size Number of its leaves.
     */
    public fun checkpointStored(size: Int) {}

    /** Constants and composition. */
    public companion object {
        /** Outcome of an operation that succeeded. */
        public const val OUTCOME_OK: String = "ok"

        /** Listener that ignores every event. */
        @JvmStatic
        public val NONE: CloakEvents = object : CloakEvents {}

        /**
         * Combines listeners: each event reaches every one of them, in order.
         *
         * @param listeners Listeners to combine.
         * @return One listener.
         */
        @JvmStatic
        public fun of(listeners: List<CloakEvents>): CloakEvents =
            when (listeners.size) {
                0 -> NONE
                1 -> listeners.single()
                else -> CompositeEvents(listeners.toList())
            }
    }
}

/**
 * Several listeners as one.
 *
 * @property listeners Listeners, in order.
 */
private class CompositeEvents(
    private val listeners: List<CloakEvents>,
) : CloakEvents {
    /** Reports to every listener. */
    override fun operationCompleted(operation: String, outcome: String, duration: Duration) =
        listeners.forEach { it.operationCompleted(operation, outcome, duration) }

    /** Reports to every listener. */
    override fun checkpointConflict(operation: String) = listeners.forEach { it.checkpointConflict(operation) }

    /** Reports to every listener. */
    override fun logEntryAppended(kind: String) = listeners.forEach { it.logEntryAppended(kind) }

    /** Reports to every listener. */
    override fun checkpointStored(size: Int) = listeners.forEach { it.checkpointStored(size) }
}
