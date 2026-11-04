package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.uuid.Uuid

/**
 * Write pauses (`PROTOCOL.md` §7.5): a member who keeps writing cannot keep a checkpoint from
 * being taken, and no member can keep a vault paused or keep an admin from pausing it.
 */
class WritePauseTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()
    private val carol: TestClient = cloak.user()
    private val vault: VaultId = cloak.createVault(alice)
    private val node = cloak.node(alice, vault)

    init {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.addMember(alice, vault, carol, Role.VIEWER)
        cloak.write(bob, vault, node, "general")
    }

    @Test
    fun `a paused rotation goes through however much a member writes, and the pause ends with it`() {
        val rotation = cloak.rotation(alice, vault, removed = listOf(bob), recipients = listOf(alice to 1, carol to 1))
        val until = cloak.server.members.pauseWrites(alice.id, listOf(vault))

        repeat(5) {
            val busy = assertCloakError(CloakErrorCode.BUSY) { cloak.write(bob, vault, node, "general") }
            assertTrue(busy.retryAfterSeconds in 1..2, "a writer retries soon, not after the whole pause")
        }
        assertEquals(cloak.clock.now + 30.seconds, until)
        cloak.server.members.rotate(alice.id, vault, rotation)

        cloak.write(alice, vault, node, "general")
    }

    @Test
    fun `the holder's own writes wait too, and releasing ends only one's own pause`() {
        cloak.server.members.pauseWrites(bob.id, listOf(vault))
        assertCloakError(CloakErrorCode.BUSY) { cloak.write(bob, vault, node, "general") }
        cloak.server.members.releaseWritePauses(alice.id, listOf(vault))
        assertCloakError(CloakErrorCode.BUSY) { cloak.write(alice, vault, node, "general") }

        cloak.server.members.releaseWritePauses(bob.id, listOf(vault))
        cloak.write(alice, vault, node, "general")
    }

    @Test
    fun `an editor never replaces another's pause, and an admin replaces anyone's`() {
        cloak.server.members.pauseWrites(alice.id, listOf(vault))
        val held = assertCloakError(CloakErrorCode.PAUSE_HELD) { cloak.server.members.pauseWrites(bob.id, listOf(vault)) }
        assertEquals(vault, held.vaultId)
        cloak.server.members.releaseWritePauses(alice.id, listOf(vault))

        cloak.server.members.pauseWrites(bob.id, listOf(vault))
        cloak.server.members.pauseWrites(alice.id, listOf(vault))
        // Alice holds it now: Bob's release changes nothing.
        cloak.server.members.releaseWritePauses(bob.id, listOf(vault))
        assertCloakError(CloakErrorCode.BUSY) { cloak.write(bob, vault, node, "general") }
    }

    @Test
    fun `an editor pauses a vault once per interval, renewals included, and an admin as often as needed`() {
        cloak.server.members.pauseWrites(bob.id, listOf(vault))
        val limited = assertCloakError(CloakErrorCode.RATE_LIMITED) { cloak.server.members.pauseWrites(bob.id, listOf(vault)) }
        assertEquals(300, limited.retryAfterSeconds)
        cloak.server.members.releaseWritePauses(bob.id, listOf(vault))
        assertCloakError(CloakErrorCode.RATE_LIMITED) { cloak.server.members.pauseWrites(bob.id, listOf(vault)) }

        cloak.clock.advance(5.minutes)
        cloak.server.members.pauseWrites(bob.id, listOf(vault))
        cloak.server.members.releaseWritePauses(bob.id, listOf(vault))
        repeat(3) { cloak.server.members.pauseWrites(alice.id, listOf(vault)) }
    }

    @Test
    fun `a pause runs out on its own`() {
        cloak.server.members.pauseWrites(alice.id, listOf(vault))
        cloak.clock.advance(29.seconds)
        assertCloakError(CloakErrorCode.BUSY) { cloak.write(bob, vault, node, "general") }
        cloak.clock.advance(1.seconds)
        cloak.write(bob, vault, node, "general")
    }

    @Test
    fun `an editor's departure with a checkpoint ends their pause`() {
        cloak.server.members.pauseWrites(bob.id, listOf(vault))
        cloak.leave(bob, vault, withCheckpoint = true)
        cloak.write(alice, vault, node, "general")
    }

    @Test
    fun `pausing needs an editor in every vault named, and pauses all of them or none`() {
        val other = cloak.createVault(alice)
        cloak.addMember(alice, other, bob, Role.EDITOR)
        cloak.write(alice, other, cloak.node(alice, other), "general")
        cloak.server.members.pauseWrites(alice.id, listOf(other))
        cloak.server.members.releaseWritePauses(alice.id, listOf(other))
        cloak.server.members.pauseWrites(alice.id, listOf(other))

        val held = assertCloakError(CloakErrorCode.PAUSE_HELD) { cloak.server.members.pauseWrites(bob.id, listOf(vault, other)) }
        assertEquals(other, held.vaultId)
        cloak.write(alice, vault, node, "general")

        assertCloakError(CloakErrorCode.ROLE_REQUIRED) { cloak.server.members.pauseWrites(carol.id, listOf(vault)) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.members.pauseWrites(carol.id, listOf(other)) }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.members.pauseWrites(alice.id, listOf(vault, vault)) }
    }
}
