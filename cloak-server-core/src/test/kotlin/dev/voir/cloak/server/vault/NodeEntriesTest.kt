package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.protocol.LogRules
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Signed node entries (`PROTOCOL.md` §7.7) and the place rule they give writes (§8.4 rule 6): a
 * write with content stands in its node's home once the node is created there, and elsewhere once
 * its owner shared the section there.
 */
class NodeEntriesTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()
    private val home: VaultId = cloak.createVault(alice)

    @Test
    fun `an editor creates a node once, owned by themselves`() {
        cloak.addMember(alice, home, bob, Role.EDITOR)
        val node = cloak.node(bob, home, "server-1")
        cloak.write(alice, home, node, "general")

        val again = cloak.entry(bob, home, LogEntryKind.NODE_CREATED, nodeId = node, nodeKey = "server-1")
        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.server.vaults.appendNodeEntry(bob.id, home, again) }
        // Alice cannot create a node claimed for Bob: its id derives from its author.
        val claimed = cloak.entry(alice, home, LogEntryKind.NODE_CREATED, nodeId = NodeOrigin(bob.id, home, NodeKey("server-2")).nodeId, nodeKey = "server-2")
        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.server.vaults.appendNodeEntry(alice.id, home, claimed) }
    }

    @Test
    fun `a viewer creates no node, and other kinds do not pass as node entries`() {
        cloak.addMember(alice, home, bob, Role.VIEWER)
        assertCloakError(CloakErrorCode.ROLE_REQUIRED) { cloak.node(bob, home) }
        val deletion = cloak.entry(alice, home, LogEntryKind.VAULT_DELETED)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.vaults.appendNodeEntry(alice.id, home, deletion) }
    }

    @Test
    fun `a write stands in the home only once the node is created there`() {
        val origin = NodeOrigin(alice.id, home, NodeKey("server-1"))
        val node = cloak.know(origin)

        val missing = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, home, node, "general") }
        assertEquals("not_shared", missing.fieldErrors.single().code)
        assertEquals("/nodeId", missing.fieldErrors.single().pointer)

        cloak.node(alice, home, "server-1")
        assertEquals(1, cloak.write(alice, home, node, "general").input.dataVersion)
    }

    @Test
    fun `a write whose node does not derive from its signed origin is refused`() {
        val node = cloak.node(alice, home, "server-1")
        val input = cloak.writeInput(alice, home, node, "general")
        val ref = SectionRef(home, node, SectionName("general"))

        val bad = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.sections.write(alice.id, ref, input.copy(nodeKey = "server-2")) }
        assertEquals("bad_node", bad.fieldErrors.single().code)
        val empty = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.sections.write(alice.id, ref, input.copy(nodeKey = "")) }
        assertEquals("node_key", empty.fieldErrors.single().code)
    }

    @Test
    fun `a shared section stands elsewhere from its share on, and stops with the unshare`() {
        val node = cloak.node(alice, home)
        val team = cloak.createVault(alice)
        val before = cloak.writeInput(alice, home, node, "notes")

        val unshared = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, team, node, "notes") }
        assertEquals("not_shared", unshared.fieldErrors.single().code)

        cloak.share(alice, team, node, "notes")
        cloak.write(alice, team, node, "notes")
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, team, node, "secrets") }

        val unshare = cloak.entry(alice, team, LogEntryKind.NODE_UNSHARED, nodeId = node, sections = "notes")
        cloak.server.vaults.appendNodeEntry(alice.id, team, unshare)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, team, node, "notes") }
        // A deletion carries nothing to read, so it needs no place, but its node must derive.
        val forged = cloak.writeInput(alice, team, node, "notes", deleted = true).copy(nodeKey = "other")
        val badDeletion = assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.sections.write(alice.id, SectionRef(team, node, SectionName("notes")), forged)
        }
        assertEquals("bad_node", badDeletion.fieldErrors.single().code)
        cloak.write(alice, team, node, "notes", deleted = true)

        cloak.share(alice, team, node)
        cloak.write(alice, team, node, "notes")
        cloak.write(alice, team, node, "secrets")
        // The home needs no share, and a write cites its own vault's head.
        cloak.server.sections.write(alice.id, SectionRef(home, node, SectionName("notes")), before)
    }

    @Test
    fun `only an admin owner shares, into a vault other than the home`() {
        val node = cloak.node(alice, home)
        val bobs = cloak.createVault(bob)
        cloak.addMember(bob, bobs, alice, Role.EDITOR)

        assertCloakError(CloakErrorCode.ROLE_REQUIRED) { cloak.share(alice, bobs, node) }
        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.share(alice, home, node) }
        cloak.addMember(alice, home, bob, Role.ADMIN)
        val notOwner = cloak.entry(
            bob, bobs, LogEntryKind.NODE_SHARED, nodeId = node, homeVaultId = home, nodeKey = cloak.originOf(node).nodeKey.value, sections = "*",
        )
        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.server.vaults.appendNodeEntry(bob.id, bobs, notOwner) }
    }

    @Test
    fun `a share holds at most 1000 names`() {
        val node = cloak.node(alice, home)
        val team = cloak.createVault(alice)
        val names = (0 until LogRules.MAX_SHARE_NAMES).map { "n" + it.toString().padStart(4, '0') }
        names.chunked(500).forEach { chunk -> cloak.share(alice, team, node, chunk.joinToString(",")) }
        // Names already shared do not count again.
        cloak.share(alice, team, node, "n0000,n0001")

        val more = cloak.entry(
            alice, team, LogEntryKind.NODE_SHARED,
            nodeId = node, homeVaultId = home, nodeKey = cloak.originOf(node).nodeKey.value, sections = "one_more",
        )
        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.server.vaults.appendNodeEntry(alice.id, team, more) }
        cloak.share(alice, team, node, "*")
    }

    @Test
    fun `a node key is well-formed UTF-8 of 1 to 255 bytes, lone surrogates refused`() {
        assertTrue(NodeKey.isValid("server-1"))
        assertTrue(NodeKey.isValid("é".repeat(127)))
        assertFalse(NodeKey.isValid("é".repeat(128)))
        assertFalse(NodeKey.isValid(""))
        assertFalse(NodeKey.isValid("a\uD800b"))
        assertFalse(NodeKey.isValid("\uDC00"))
    }

    @Test
    fun `a share ends when its owner is removed`() {
        val node = cloak.node(alice, home)
        val bobs = cloak.createVault(bob)
        cloak.addMember(bob, bobs, alice, Role.ADMIN)
        cloak.share(alice, bobs, node)
        cloak.write(alice, bobs, node, "general")

        cloak.rotate(bob, bobs, removed = listOf(alice), recipients = listOf(bob to 1), checkpoint = cloak.checkpoint(bob, bobs))
        cloak.addMember(bob, bobs, alice, Role.EDITOR)

        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, bobs, node, "general") }
        assertEquals(0L, cloak.number("select count(*) from cloak.node_shares where vault_id = '${bobs.value}'"))
    }
}
