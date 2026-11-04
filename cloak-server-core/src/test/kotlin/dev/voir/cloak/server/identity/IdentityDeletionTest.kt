package dev.voir.cloak.server.identity

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.DeliverEnvelopeCommand
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import java.util.concurrent.Callable
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Deleting identities (`PROTOCOL.md` §5.7), by the user and by the host. */
class IdentityDeletionTest {
    private val cloak = CloakFixture()

    @Test
    fun `a user deletes their identity only once they belong to no vault`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        cloak.server.members.accept(bob.id, vault)

        assertCloakError(CloakErrorCode.IDENTITY_IN_VAULTS) { cloak.deleteIdentity(bob) }
        cloak.leave(bob, vault, withCheckpoint = false)
        val statement = cloak.deletion(bob)
        cloak.server.identity.delete(bob.id, statement)

        val keys = cloak.server.identity.userKeys(alice.id, bob.id)
        assertTrue(keys.deleted)
        assertNull(keys.hostUserId)
        assertEquals(listOf(1), keys.versions.map { it.keys.keyVersion })
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.identity.get(bob.id) }
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.identity.delete(bob.id, statement) }
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.vaults.list(bob.id) }
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.identity.requireNotDeleted(bob.id) }
        assertEquals(1L, cloak.number("select count(*) from cloak.identities where deleted_at is not null and private_key_bundle is null"))
    }

    @Test
    fun `refuses a deletion statement out of its window, of another version or badly signed`() {
        val alice = cloak.user()
        val now = cloak.clock.now.epochSeconds

        val late = assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.identity.delete(alice.id, cloak.deletion(alice, notAfter = now - 1))
        }
        assertEquals("expired", late.fieldErrors.single().code)
        val far = assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.identity.delete(alice.id, cloak.deletion(alice, notAfter = now + 601))
        }
        assertEquals("maximum", far.fieldErrors.single().code)
        assertCloakError(CloakErrorCode.CREDENTIALS_VERSION_CONFLICT) {
            cloak.server.identity.delete(alice.id, cloak.deletion(alice, credentialsVersion = 2))
        }
        val statement = cloak.deletion(alice)
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.identity.delete(alice.id, statement.copy(notAfter = statement.notAfter - 1))
        }

        cloak.server.identity.delete(alice.id, cloak.deletion(alice, notAfter = now + 600))
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.identity.get(alice.id) }
    }

    @Test
    fun `a statement signed before a credentials change no longer deletes`() {
        val alice = cloak.user()
        val statement = cloak.deletion(alice)
        cloak.server.identity.updateCredentials(alice.id, cloak.credentialsChange(alice, expected = 1))

        assertCloakError(CloakErrorCode.CREDENTIALS_VERSION_CONFLICT) { cloak.server.identity.delete(alice.id, statement) }
        cloak.server.identity.delete(alice.id, cloak.deletion(alice, credentialsVersion = 2))
    }

    @Test
    fun `a vault never accepted holds no account, and its envelope goes with the identity`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.EDITOR)

        cloak.deleteIdentity(bob)

        // Bob stays in the log and the member list until an admin removes him with a rotation.
        assertEquals(1L, cloak.number("select count(*) from cloak.vault_members where user_id = '${bob.id.value}' and key_envelope is null"))
        assertEquals(2L, cloak.number("select count(*) from cloak.vault_members where vault_id = '${vault.value}'"))
        assertTrue(cloak.server.identity.userKeys(alice.id, bob.id).deleted)
    }

    @Test
    fun `a deleted vault no longer keeps its members from deleting their identity`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)

        cloak.server.vaults.delete(alice.id, vault, cloak.entry(alice, vault, LogEntryKind.VAULT_DELETED))

        cloak.deleteIdentity(alice)
        cloak.deleteIdentity(bob)
    }

    @Test
    fun `a deleted user id never registers again, with old keys or new`() {
        val alice = cloak.user()
        cloak.deleteIdentity(alice)
        val again = TestClient(alice.hostUserId)

        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.identity.register(alice.hostUserId, alice.registration()) }
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.identity.register(again.hostUserId, again.registration()) }
    }

    @Test
    fun `racing registrations of one user id store exactly one identity and fail the rest cleanly`() {
        val host = TestClient()
        val clients = List(8) { TestClient(host.hostUserId) }
        val barrier = CyclicBarrier(clients.size)
        val pool = Executors.newFixedThreadPool(clients.size)

        val outcomes = try {
            pool.invokeAll(
                clients.map { client ->
                    Callable {
                        barrier.await(10, TimeUnit.SECONDS)
                        try {
                            cloak.server.identity.register(client.hostUserId, client.registration())
                            "registered"
                        } catch (refusal: CloakException) {
                            refusal.code.code
                        }
                    }
                },
            ).map { it.get() }
        } finally {
            pool.shutdown()
        }

        assertEquals(1, outcomes.count { it == "registered" })
        assertEquals(clients.size - 1, outcomes.count { it == CloakErrorCode.ALREADY_EXISTS.code })
    }

    @Test
    fun `the host erases a user, so their sole vaults go and shared vaults keep the membership without envelopes`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val alone = cloak.createVault(alice)
        val shared = cloak.createVault(bob)
        cloak.addMember(bob, shared, alice, Role.EDITOR)

        assertTrue(cloak.server.identity.erase(alice.hostUserId))
        assertFalse(cloak.server.identity.erase(alice.hostUserId))

        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.get(bob.id, alone) }
        assertEquals(0L, cloak.number("select count(*) from cloak.vaults where id = '${alone.value}'"))
        assertEquals(
            1L,
            cloak.number("select count(*) from cloak.vault_members where user_id = '${alice.id.value}' and key_envelope is null"),
        )
        assertTrue(cloak.server.identity.userKeys(bob.id, alice.id).deleted)
        assertNull(cloak.server.access.role(alice.hostUserId.value, shared.value))
        assertEquals(Role.OWNER, cloak.server.access.role(bob.hostUserId.value, shared.value))
        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.server.vaults.get(alice.id, shared) }
    }

    @Test
    fun `nobody seals a vault key to an erased member, and an admin removes them with a rotation`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val carol = cloak.user()
        val vault = cloak.createVault(bob)
        cloak.addMember(bob, vault, alice, Role.EDITOR)
        cloak.addMember(bob, vault, carol, Role.VIEWER)
        cloak.server.identity.erase(alice.hostUserId)
        val keyVersion = cloak.vault(bob, vault).keyVersion

        assertCloakError(CloakErrorCode.IDENTITY_DELETED) {
            cloak.server.members.deliverEnvelope(bob.id, vault, alice.id, DeliverEnvelopeCommand(keyVersion, 1, TestBlobs.envelope()))
        }
        assertCloakError(CloakErrorCode.RECIPIENTS_MISMATCH) {
            cloak.rotate(bob, vault, recipients = listOf(bob to 1, alice to 1, carol to 1))
        }
        // The erased member stays in the log until removed; a rotation that keeps them seals to the others only.
        cloak.rotate(bob, vault, recipients = listOf(bob to 1, carol to 1))
        cloak.rotate(bob, vault, removed = listOf(alice), recipients = listOf(bob to 1, carol to 1))

        assertEquals(listOf(Role.OWNER, Role.VIEWER), listOf(bob, carol).map { cloak.vault(it, vault).role })
        assertEquals(0L, cloak.number("select count(*) from cloak.vault_members where user_id = '${alice.id.value}'"))
    }

    @Test
    fun `an erased user cannot be added to a vault`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val vault: VaultId = cloak.createVault(bob)
        cloak.server.identity.erase(alice.hostUserId)

        assertCloakError(CloakErrorCode.IDENTITY_DELETED) { cloak.addMember(bob, vault, alice, Role.VIEWER) }
    }

    @Test
    fun `erasing a user who never registered changes nothing`() {
        val stranger = TestClient()

        assertFalse(cloak.server.identity.erase(stranger.hostUserId))
        cloak.server.identity.register(stranger.hostUserId, stranger.registration())
    }
}
