package dev.voir.cloak.server.persistence

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.observability.CloakEvents
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import java.sql.Connection
import java.time.Duration
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** What every operation shares: database time limits, settings and events. */
class CloakContextTest {
    @Test
    fun `a vault locked too long answers busy, and nothing is applied`() {
        val cloak = CloakFixture(CloakSettings.builder().lockTimeout(Duration.ofMillis(200)).build())
        val alice = cloak.user()
        val vault = cloak.createVault(alice)

        val refusal = holdingVault(cloak, vault) { assertCloakError(CloakErrorCode.BUSY) { cloak.writeMany(alice, vault, 1) } }

        assertEquals(1, refusal.retryAfterSeconds)
        assertEquals(0L, cloak.number("select count(*) from cloak.sections"))
    }

    @Test
    fun `a statement over its budget answers busy`() {
        val cloak = CloakFixture(
            CloakSettings.builder()
                .statementTimeout(Duration.ofMillis(200))
                .checkpointStatementTimeout(Duration.ofMillis(200))
                .lockTimeout(Duration.ofSeconds(10))
                .build(),
        )
        val alice = cloak.user()
        val vault = cloak.createVault(alice)

        val refusal = holdingVault(cloak, vault) { assertCloakError(CloakErrorCode.BUSY) { cloak.writeMany(alice, vault, 1) } }

        assertEquals(5, refusal.retryAfterSeconds)
    }

    @Test
    fun `settings refuse a request limit the largest rotation would not fit in`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            CloakSettings.builder().maxRequestBytes(Limits.MIN_REQUEST_BYTES - 1).build()
        }

        assertContains(failure.message.orEmpty(), "rotation")
        assertTrue(Limits.MAX_ROTATION_REQUEST_BYTES <= Limits.MIN_REQUEST_BYTES)
        assertEquals(Limits.DEFAULT_MAX_REQUEST_BYTES, CloakFixture().server.meta().limits.maxRequestBytes)
        assertEquals(
            Limits.MIN_REQUEST_BYTES,
            CloakFixture(CloakSettings.builder().maxRequestBytes(Limits.MIN_REQUEST_BYTES).build()).server.meta().limits.maxRequestBytes,
        )
    }

    @Test
    fun `events of committed work are reported after the operation, and a refusal reports its code only`() {
        val events = RecordingEvents()
        val cloak = CloakFixture(CloakSettings.builder().events(events).build())
        val alice = cloak.user()
        val bob = cloak.user()
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.writeMany(bob, vault, 3)
        events.seen.clear()

        cloak.rotate(alice, vault, removed = listOf(bob), recipients = listOf(alice to 1))
        assertEquals(
            listOf("checkpointStored 3", "logEntryAppended member_removed", "logEntryAppended key_rotated", "operationCompleted rotateVault ok"),
            events.ofRotations(),
        )

        events.seen.clear()
        cloak.writeMany(alice, vault, 1)
        events.seen.clear()
        assertCloakError(CloakErrorCode.CHECKPOINT_CONFLICT) {
            cloak.rotate(alice, vault, recipients = listOf(alice to 2), checkpoint = TestBlobs.random(32))
        }
        assertEquals(listOf("checkpointConflict rotateVault", "operationCompleted rotateVault checkpoint_conflict"), events.ofRotations())
    }

    @Test
    fun `a failing listener never fails the request`() {
        val cloak = CloakFixture(
            CloakSettings.builder().events(
                object : CloakEvents {
                    override fun operationCompleted(operation: String, outcome: String, duration: Duration) = error("listener bug")

                    override fun logEntryAppended(kind: String) = error("listener bug")
                },
            ).build(),
        )
        val alice = cloak.user()

        cloak.createVault(alice)

        assertEquals(1, cloak.server.vaults.list(alice.id).items.size)
    }

    /** Runs [block] while another connection holds [vault]'s row lock. */
    private fun <T> holdingVault(cloak: CloakFixture, vault: VaultId, block: () -> T): T =
        cloak.dataSource.connection.use { connection: Connection ->
            connection.autoCommit = false
            connection.createStatement().use { it.execute("select 1 from cloak.vaults where id = '${vault.value}' for update") }
            try {
                block()
            } finally {
                connection.rollback()
            }
        }

    /** Records events as short strings, without their durations. */
    private class RecordingEvents : CloakEvents {
        val seen: MutableList<String> = Collections.synchronizedList(mutableListOf())

        /** Events of the rotation, without the reads a client makes to prepare it. */
        fun ofRotations(): List<String> = seen.filterNot { it.startsWith("operationCompleted") && "rotateVault" !in it }

        override fun operationCompleted(operation: String, outcome: String, duration: Duration) {
            seen += "operationCompleted $operation $outcome"
        }

        override fun checkpointConflict(operation: String) {
            seen += "checkpointConflict $operation"
        }

        override fun logEntryAppended(kind: String) {
            seen += "logEntryAppended $kind"
        }

        override fun checkpointStored(size: Int) {
            seen += "checkpointStored $size"
        }
    }
}
