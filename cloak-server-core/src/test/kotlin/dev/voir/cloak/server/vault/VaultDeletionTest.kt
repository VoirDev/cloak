package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultLogQuery
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.toJavaUuid

/**
 * Deleting a vault with an owner's signed `vault_deleted` (`PROTOCOL.md` §12.3): its content goes,
 * its log and members stay readable, and nothing more is appended.
 */
class VaultDeletionTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()
    private val vault: VaultId = cloak.createVault(alice)

    /** Deletes [vault] as Alice. */
    private fun delete() = cloak.server.vaults.delete(alice.id, vault, cloak.entry(alice, vault, LogEntryKind.VAULT_DELETED))

    @Test
    fun `erases the content, keeps the log and members, and lists the vault no more`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.server.members.accept(bob.id, vault)
        val node = cloak.node(alice, vault)
        cloak.write(alice, vault, node, "general")
        val shared = cloak.node(alice, cloak.createVault(alice))
        cloak.share(alice, vault, shared)
        cloak.server.members.pauseWrites(bob.id, listOf(vault))

        delete()

        val view = cloak.vault(bob, vault)
        assertTrue(view.deleted)
        assertNull(view.keyEnvelope)
        val log = cloak.server.vaults.log(bob.id, vault)
        assertEquals(LogEntryKind.VAULT_DELETED, log.items.last().input.kind)
        assertEquals(view.logSeq, log.headSeq)
        val batch = cloak.server.vaults.getMany(bob.id, listOf(VaultLogQuery(vault)))
        assertEquals(true, batch.single().vault?.deleted)
        assertFalse(cloak.server.vaults.list(alice.id).items.any { it.id == vault })
        assertFalse(cloak.server.vaults.list(bob.id, pending = true).items.any { it.id == vault })
        for (table in listOf("sections", "vault_keys", "nodes", "node_shares", "checkpoint_leaves", "write_pause_requests", "section_removals")) {
            assertEquals(0L, cloak.number("select count(*) from cloak.$table where vault_id = '${vault.value}'"), table)
        }
        assertEquals(2L, cloak.number("select count(*) from cloak.vault_members where vault_id = '${vault.value}' and key_envelope is null"))
        assertNull(cloak.server.access.role(bob.hostUserId.value, vault.value.toJavaUuid()))
    }

    @Test
    fun `refuses content, members and further entries once deleted`() {
        val node = cloak.node(alice, vault)
        val input = cloak.writeInput(alice, vault, node, "general")
        delete()

        val ref = SectionRef(vault, node, SectionName("general"))
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.sections.write(alice.id, ref, input) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.sections.list(alice.id, vault) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.sections.headers(alice.id, vault) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.keys(alice.id, vault) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.addMember(alice, vault, bob, Role.VIEWER) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.members.pauseWrites(alice.id, listOf(vault)) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.node(alice, vault) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { delete() }
        assertEquals(1, cloak.server.vaults.log(alice.id, vault).items.count { it.input.kind == LogEntryKind.VAULT_DELETED })
    }

    @Test
    fun `only an owner deletes, with a vault_deleted entry alone`() {
        cloak.addMember(alice, vault, bob, Role.ADMIN)

        assertCloakError(CloakErrorCode.ROLE_REQUIRED) {
            cloak.server.vaults.delete(bob.id, vault, cloak.entry(bob, vault, LogEntryKind.VAULT_DELETED))
        }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.vaults.delete(alice.id, vault, cloak.entry(alice, vault, LogEntryKind.KEY_ROTATED, keyCommitment = TestBlobs.random(32)))
        }
        assertCloakError(CloakErrorCode.LOG_REJECTED) {
            cloak.server.vaults.delete(alice.id, vault, cloak.entry(alice, vault, LogEntryKind.VAULT_DELETED, requestEnd = false))
        }
        assertFalse(cloak.vault(alice, vault).deleted)
    }
}
