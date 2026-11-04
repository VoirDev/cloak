package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.Role
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.toJavaUuid

/**
 * Accepting vaults (`PROTOCOL.md` §12.4): unsigned help against being added unasked. A person added
 * is a member by the log at once, but is listed, and counted by the host, only once they accept.
 */
class AcceptanceTest {
    private val cloak = CloakFixture(CloakSettings.builder().maxPendingInvitations(2).build())
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()

    @Test
    fun `the creator has accepted, an added member is pending until they accept`() {
        val vault = cloak.createVault(alice)
        val created = cloak.vault(alice, vault)
        assertTrue(created.accepted)
        assertNull(created.addedByUserId)

        cloak.addMember(alice, vault, bob, Role.VIEWER)
        val pending = cloak.vault(bob, vault)
        assertFalse(pending.accepted)
        assertEquals(alice.id, pending.addedByUserId)
        assertEquals(emptyList(), cloak.server.vaults.list(bob.id).items)
        assertEquals(listOf(vault), cloak.server.vaults.list(bob.id, pending = true).items.map { it.id })
        assertNull(cloak.server.access.role(bob.hostUserId.value, vault.value.toJavaUuid()))

        cloak.server.members.accept(bob.id, vault)
        assertTrue(cloak.vault(bob, vault).accepted)
        assertEquals(listOf(vault), cloak.server.vaults.list(bob.id).items.map { it.id })
        assertEquals(emptyList(), cloak.server.vaults.list(bob.id, pending = true).items)
        assertEquals(Role.VIEWER, cloak.server.access.role(bob.hostUserId.value, vault.value.toJavaUuid()))
    }

    @Test
    fun `accepting an inviter accepts their vaults, now and later`() {
        val first = cloak.createVault(alice)
        cloak.addMember(alice, first, bob, Role.VIEWER)
        val carol = cloak.user()
        val carols = cloak.createVault(carol)
        cloak.addMember(carol, carols, bob, Role.VIEWER)

        cloak.server.members.acceptInviter(bob.id, alice.id)
        cloak.server.members.acceptInviter(bob.id, alice.id)
        val later = cloak.createVault(alice)
        cloak.addMember(alice, later, bob, Role.EDITOR)

        assertTrue(cloak.vault(bob, first).accepted)
        assertTrue(cloak.vault(bob, later).accepted)
        assertFalse(cloak.vault(bob, carols).accepted)
    }

    @Test
    fun `a user holds at most the configured pending invitations, except from inviters they accept`() {
        val vaults = List(3) { cloak.createVault(alice) }
        cloak.addMember(alice, vaults[0], bob, Role.VIEWER)
        cloak.addMember(alice, vaults[1], bob, Role.VIEWER)

        assertCloakError(CloakErrorCode.TOO_MANY_INVITATIONS) { cloak.addMember(alice, vaults[2], bob, Role.VIEWER) }
        assertEquals(2, cloak.server.meta().limits.maxPendingInvitations)

        cloak.server.members.accept(bob.id, vaults[0])
        cloak.addMember(alice, vaults[2], bob, Role.VIEWER)
        val carol = cloak.user()
        val carols = List(3) { cloak.createVault(carol) }
        assertCloakError(CloakErrorCode.TOO_MANY_INVITATIONS) { cloak.addMember(carol, carols[0], bob, Role.VIEWER) }
        cloak.server.members.acceptInviter(bob.id, carol.id)
        carols.forEach { cloak.addMember(carol, it, bob, Role.VIEWER) }
    }

    @Test
    fun `one inviter holds at most their share of a user's pending invitations`() {
        val limited = CloakFixture(CloakSettings.builder().maxPendingInvitations(3).maxPendingInvitationsPerInviter(1).build())
        val owner = limited.user()
        val other = limited.user()
        val invitee = limited.user()
        val first = limited.createVault(owner)
        val second = limited.createVault(owner)
        val others = limited.createVault(other)

        limited.addMember(owner, first, invitee, Role.VIEWER)
        assertCloakError(CloakErrorCode.TOO_MANY_INVITATIONS) { limited.addMember(owner, second, invitee, Role.VIEWER) }
        limited.addMember(other, others, invitee, Role.VIEWER)
        assertEquals(1, limited.server.meta().limits.maxPendingInvitationsPerInviter)

        limited.server.members.accept(invitee.id, first)
        limited.addMember(owner, second, invitee, Role.VIEWER)
    }

    @Test
    fun `a non-member accepts nothing`() {
        val vault = cloak.createVault(alice)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.members.accept(bob.id, vault) }
    }
}
