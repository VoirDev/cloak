package dev.voir.cloak.server.section

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

/**
 * The host removes a node's sections where the user administers the vault; the removals reach every
 * member's change feed, and the next checkpoint goes on without them (`PROTOCOL.md` §15).
 */
class NodePurgeTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()
    private val mine: VaultId = cloak.createVault(alice)
    private val bobs: VaultId = cloak.createVault(bob)
    private val node = cloak.node(alice, mine)

    @Test
    fun `removes the node where the user administers the vault, and nowhere else`() {
        // Alice shares her node into Bob's vault as an admin there, then edits it as an editor.
        cloak.addMember(bob, bobs, alice, Role.ADMIN)
        cloak.share(alice, bobs, node, "notes")
        cloak.setRole(bob, bobs, alice, Role.EDITOR)
        cloak.write(alice, mine, node, "general")
        cloak.write(alice, mine, node, "secrets")
        cloak.write(alice, mine, node, "secrets", deleted = true)
        cloak.write(alice, bobs, node, "notes")
        // Changes 1 to 3: two writes and a deletion.
        val lastWrite = 3L

        val remaining = cloak.server.nodes.purge(alice.hostUserId.value, node.value.toJavaUuid())

        assertEquals(setOf(bobs.value.toJavaUuid()), remaining)
        assertEquals(0L, cloak.number("select count(*) from cloak.sections where vault_id = '${mine.value}'"))
        assertEquals(0L, cloak.number("select live_section_count + stored_section_count from cloak.vaults where id = '${mine.value}'"))
        val feed = cloak.server.sections.list(alice.id, mine, afterChange = lastWrite)
        assertEquals(listOf("general", "secrets"), feed.removed.map { it.sectionName.value }.sorted())
        assertTrue(feed.removed.all { it.changeSeq > lastWrite && it.nodeId == node })
        assertEquals(feed.lastChangeSeq, feed.throughChangeSeq)
        // The next checkpoint simply goes on without the node.
        cloak.rotate(alice, mine, recipients = listOf(alice to 1))
    }

    @Test
    fun `a deleted user removes nothing`() {
        // With Bob in it, erasing Alice keeps the vault: it is not hers alone.
        cloak.addMember(alice, mine, bob, Role.VIEWER)
        cloak.write(alice, mine, node, "general")
        cloak.server.identity.erase(HostUserId.of(alice.hostUserId.value))

        assertEquals(setOf(mine.value.toJavaUuid()), cloak.server.nodes.purge(alice.hostUserId.value, node.value.toJavaUuid()))
    }

    @Test
    fun `a page of the feed covers writes and removals without skipping a change`() {
        val nodes = cloak.writeMany(alice, mine, 6)
        cloak.server.nodes.purge(alice.hostUserId.value, nodes[1].value.toJavaUuid())
        cloak.server.nodes.purge(alice.hostUserId.value, nodes[4].value.toJavaUuid())
        cloak.write(alice, mine, nodes[0], "general")

        val seen = mutableListOf<Long>()
        var after = 0L
        do {
            val page = cloak.server.sections.headers(alice.id, mine, after.takeIf { it > 0 }, limit = 2)
            assertTrue(page.items.size <= 2 && page.removed.size <= 2)
            seen += page.items.map { it.changeSeq } + page.removed.map { it.changeSeq }
            assertTrue((page.items.map { it.changeSeq } + page.removed.map { it.changeSeq }).all { it in (after + 1)..page.throughChangeSeq })
            after = page.throughChangeSeq
        } while (page.throughChangeSeq < page.lastChangeSeq)

        // Writes 1 to 6; nodes[1] (2) and nodes[4] (5) removed at 7 and 8; nodes[0] (1) written again at 9.
        assertEquals(listOf(3L, 4L, 6L, 7L, 8L, 9L), seen.sorted())
    }
}
