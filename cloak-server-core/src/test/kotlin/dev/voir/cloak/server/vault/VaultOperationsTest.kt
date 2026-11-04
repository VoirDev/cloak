package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.vault.domain.CreateVaultCommand
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.uuid.Uuid

/** Creating, listing, reading and deleting vaults; their logs and keys. */
class VaultOperationsTest {
    private val cloak = CloakFixture()

    @Test
    fun `creates a vault with its owner, first key and log entry`() {
        val alice = cloak.user()

        val id = cloak.createVault(alice)

        val vault = cloak.vault(alice, id)
        val log = cloak.server.vaults.log(alice.id, id)
        assertEquals(Role.OWNER, vault.role)
        assertEquals(1, vault.keyVersion)
        assertEquals(1, vault.envelopeUserKeyVersion)
        assertEquals(listOf(LogEntryKind.VAULT_CREATED), log.items.map { it.input.kind })
        assertEquals(vault.logHeadHash, log.items.single().entryHash)
        assertEquals(listOf(1), cloak.server.vaults.keys(alice.id, id).map { it.version })
    }

    @Test
    fun `refuses a taken id, another author's keys and a vault for someone else`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val id = cloak.createVault(alice)
        assertCloakError(CloakErrorCode.ALREADY_EXISTS) { cloak.createVault(bob, id) }

        val other = VaultId(Uuid.random())
        val forBob = cloak.entry(alice, other, LogEntryKind.VAULT_CREATED, subject = bob, role = Role.OWNER, keyVersion = 1, keyCommitment = TestBlobs.random(32), seq = 1)
        assertCloakError(CloakErrorCode.LOG_REJECTED) {
            cloak.server.vaults.create(alice.id, CreateVaultCommand(other, TestBlobs.envelope(), forBob))
        }
    }

    @Test
    fun `hides a vault from non-members and lets only an owner delete it`() {
        val alice = cloak.user()
        val bob = cloak.user()
        val id = cloak.createVault(alice)

        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.get(bob.id, id) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.log(bob.id, id) }

        cloak.addMember(alice, id, bob, Role.ADMIN)
        cloak.server.members.accept(bob.id, id)
        assertCloakError(CloakErrorCode.ROLE_REQUIRED) {
            cloak.server.vaults.delete(bob.id, id, cloak.entry(bob, id, LogEntryKind.VAULT_DELETED))
        }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.vaults.delete(alice.id, id, cloak.entry(alice, id, LogEntryKind.KEY_ROTATED))
        }
        cloak.server.vaults.delete(alice.id, id, cloak.entry(alice, id, LogEntryKind.VAULT_DELETED))

        val deleted = cloak.vault(alice, id)
        assertTrue(deleted.deleted)
        assertEquals(LogEntryKind.VAULT_DELETED, cloak.server.vaults.log(bob.id, id).items.last().input.kind)
    }

    @Test
    fun `lists the caller's vaults newest first, page by page`() {
        val alice = cloak.user()
        val ids = (1..3).map {
            cloak.clock.advance(1.seconds)
            cloak.createVault(alice)
        }

        val first = cloak.server.vaults.list(alice.id, PageRequest(limit = 2))
        val second = cloak.server.vaults.list(alice.id, PageRequest(limit = 2, cursor = first.nextCursor))

        assertEquals(ids.reversed(), (first.items + second.items).map { it.id })
        assertNull(second.nextCursor)
    }
}
