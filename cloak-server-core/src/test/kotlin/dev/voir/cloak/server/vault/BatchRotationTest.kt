package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultLogQuery
import dev.voir.cloak.server.vault.domain.VaultRotation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Removing people from a group of vaults is one request, all or none, so nobody is left half
 * removed; reading a group of vaults is one request that answers for every vault (`PROTOCOL.md` §12.4).
 */
class BatchRotationTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()
    private val first: VaultId = cloak.createVault(alice)
    private val second: VaultId = cloak.createVault(alice)

    init {
        listOf(first, second).forEach { vault ->
            cloak.addMember(alice, vault, bob, Role.EDITOR)
            cloak.write(bob, vault, cloak.node(alice, vault), "general")
        }
    }

    @Test
    fun `removes a member from every vault in one request, and ends the caller's pauses`() {
        cloak.server.members.pauseWrites(alice.id, listOf(first, second))
        val rotations = listOf(first, second).map { VaultRotation(it, cloak.rotation(alice, it, removed = listOf(bob), recipients = listOf(alice to 1))) }

        val vaults = cloak.server.members.rotateMany(alice.id, rotations)

        assertEquals(listOf(first, second), vaults.map { it.id })
        assertTrue(vaults.all { it.keyVersion == 2 })
        listOf(first, second).forEach { vault ->
            assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.vault(bob, vault) }
            cloak.write(alice, vault, cloak.node(alice, vault), "general")
        }
    }

    @Test
    fun `a refusal of one rotation applies none of them and names its vault`() {
        val good = VaultRotation(first, cloak.rotation(alice, first, removed = listOf(bob), recipients = listOf(alice to 1)))
        // Seals the new key to Bob, whom the rotation removes.
        val bad = VaultRotation(second, cloak.rotation(alice, second, removed = listOf(bob), recipients = listOf(alice to 1, bob to 1)))

        val refused = assertCloakError(CloakErrorCode.RECIPIENTS_MISMATCH) { cloak.server.members.rotateMany(alice.id, listOf(good, bad)) }

        assertEquals(second, refused.vaultId)
        assertEquals(1, cloak.vault(alice, first).keyVersion)
        assertEquals(Role.EDITOR, cloak.vault(bob, first).role)
    }

    @Test
    fun `a vault the caller cannot see refuses the whole batch, and vaults repeat never`() {
        val hidden = cloak.createVault(bob)
        val rotation = VaultRotation(first, cloak.rotation(alice, first, recipients = listOf(alice to 1, bob to 1)))
        val foreign = VaultRotation(hidden, cloak.rotation(bob, hidden, recipients = listOf(bob to 1)))

        val refused = assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.members.rotateMany(alice.id, listOf(rotation, foreign)) }
        assertEquals(hidden, refused.vaultId)
        assertEquals(1, cloak.vault(alice, first).keyVersion)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.members.rotateMany(alice.id, listOf(rotation, rotation)) }
    }

    @Test
    fun `a batch read answers for every vault asked, in order, hiding the ones the caller cannot see`() {
        val hidden = cloak.createVault(bob)
        val head = cloak.vault(alice, second).logSeq

        val items = cloak.server.vaults.getMany(alice.id, listOf(VaultLogQuery(second, afterSeq = head - 1), VaultLogQuery(hidden), VaultLogQuery(first)))

        assertEquals(listOf(second, hidden, first), items.map { it.vaultId })
        assertEquals(listOf(head), items[0].log?.items?.map { it.input.seq })
        assertFalse(items[1].found)
        assertNull(items[1].log)
        assertEquals(cloak.vault(alice, first).logSeq, items[2].log?.headSeq)
        assertEquals(cloak.vault(alice, first).logSeq.toInt(), items[2].log?.items?.size)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.vaults.getMany(alice.id, listOf(VaultLogQuery(first), VaultLogQuery(first))) }
    }
}
