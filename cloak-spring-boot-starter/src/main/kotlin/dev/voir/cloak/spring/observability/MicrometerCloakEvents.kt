package dev.voir.cloak.spring.observability

import dev.voir.cloak.server.observability.CloakEvents
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Timer
import org.springframework.beans.factory.ObjectProvider
import java.time.Duration

/**
 * Reports Cloak's events as Micrometer meters, to the host's [MeterRegistry] when it has one:
 *
 * - `cloak.requests`, a timer tagged `operation` (the `operationId`) and `outcome` (`ok` or the
 *   error code);
 * - `cloak.refusals`, a counter tagged `code`, for every operation that did not succeed;
 * - `cloak.checkpoint.conflicts`, a counter tagged `operation`;
 * - `cloak.log.entries`, a counter tagged `kind`;
 * - `cloak.checkpoint.size`, a distribution of the leaves of stored checkpoints.
 *
 * Tags take a closed set of values: never an id of a user, a vault or anything else.
 *
 * @property registry The host's registry, looked up per event so the order beans start in does not matter.
 */
internal class MicrometerCloakEvents(
    private val registry: ObjectProvider<MeterRegistry>,
) : CloakEvents {
    /** Times the operation and counts a refusal. */
    override fun operationCompleted(operation: String, outcome: String, duration: Duration) {
        val meters = registry.ifAvailable ?: return
        Timer.builder("cloak.requests")
            .description("Cloak API operations")
            .tag("operation", operation)
            .tag("outcome", outcome)
            .register(meters)
            .record(duration)
        if (outcome != CloakEvents.OUTCOME_OK) {
            Counter.builder("cloak.refusals").description("Cloak operations that did not succeed").tag("code", outcome)
                .register(meters).increment()
        }
    }

    /** Counts a checkpoint conflict. */
    override fun checkpointConflict(operation: String) {
        val meters = registry.ifAvailable ?: return
        Counter.builder("cloak.checkpoint.conflicts").description("Checkpoints built again because writes slipped in")
            .tag("operation", operation).register(meters).increment()
    }

    /** Counts a stored log entry. */
    override fun logEntryAppended(kind: String) {
        val meters = registry.ifAvailable ?: return
        Counter.builder("cloak.log.entries").description("Vault log entries stored").tag("kind", kind).register(meters).increment()
    }

    /** Records a stored checkpoint's size. */
    override fun checkpointStored(size: Int) {
        val meters = registry.ifAvailable ?: return
        DistributionSummary.builder("cloak.checkpoint.size").description("Leaves of stored checkpoints").baseUnit("leaves")
            .register(meters).record(size.toDouble())
    }
}
