package dev.voir.cloak.server.section

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.section.domain.SectionWrite
import dev.voir.cloak.server.vault.domain.Role
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Every read that returns ciphertext holds whole sections, at least one, within one page's budget
 * ([Limits.MAX_PAGE_BYTES]) and page size, and its cursors cover everything exactly once.
 */
class ReadBudgetTest {
    private val cloak = CloakFixture()
    private val alice = cloak.user()
    private val bob = cloak.user()
    private val vault = cloak.createVault(alice)

    @Test
    fun `a node read pages its sections within the budget, and its cursors cover each once`() {
        val shared = cloak.createVault(alice)
        val node = cloak.node(alice, vault)
        cloak.share(alice, shared, node)
        val written = (1..9).map { cloak.write(alice, vault, node, "large_$it", blocks = LARGEST_BLOCKS) } +
            (1..9).map { cloak.write(alice, shared, node, "large_$it", blocks = LARGEST_BLOCKS) } +
            cloak.write(alice, vault, node, "small") +
            cloak.write(alice, vault, node, "gone").let { cloak.write(alice, vault, node, "gone", deleted = true) }

        val pages = generateSequence(cloak.server.nodes.get(alice.id, node)) { page ->
            page.nextCursor?.let { cloak.server.nodes.get(alice.id, node, it) }
        }.toList()

        assertTrue(pages.size >= 3)
        pages.forEach { page -> assertWithinBudget(page.sections) }
        val read = pages.flatMap { it.sections }
        assertEquals(written.map { it.section }.sortedWith(NODE_ORDER), read.map { it.section })
        assertEquals(written.associate { it.section to it.writeHash }, read.associate { it.section to it.writeHash })
    }

    @Test
    fun `a node read holds at most a page of sections, however small`() {
        val node = cloak.node(alice, vault)
        val written = (1..PageRequest.MAX_LIMIT + 20).map { cloak.write(alice, vault, node, "s$it") }

        val first = cloak.server.nodes.get(alice.id, node)
        val second = cloak.server.nodes.get(alice.id, node, checkNotNull(first.nextCursor))

        assertEquals(PageRequest.MAX_LIMIT, first.sections.size)
        assertEquals(20, second.sections.size)
        assertEquals(null, second.nextCursor)
        assertEquals(written.map { it.section }.toSet(), (first.sections + second.sections).map { it.section }.toSet())
    }

    @Test
    fun `a node read refuses a cursor of another node or a malformed one`() {
        val node = cloak.node(alice, vault)
        val other = cloak.node(alice, vault)
        repeat(9) { cloak.write(alice, vault, node, "large_$it", blocks = LARGEST_BLOCKS) }
        cloak.write(alice, vault, other, "general")
        val cursor = checkNotNull(cloak.server.nodes.get(alice.id, node).nextCursor)

        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.nodes.get(alice.id, other, cursor) }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.nodes.get(alice.id, node, "not-a-cursor") }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.nodes.get(bob.id, node) }
    }

    @Test
    fun `a batch of nodes shares one budget, and its cursors and unread nodes cover everything once`() {
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        val nodes = List(5) { cloak.node(alice, vault) }
        val written = nodes.flatMap { node -> (1..3).map { cloak.write(alice, vault, node, "large_$it", blocks = LARGEST_BLOCKS) } } +
            cloak.write(alice, vault, nodes[0], "small")
        val missing = List(3) { NodeId(Uuid.random()) }

        val read = mutableListOf<SectionWrite>()
        val missed = mutableSetOf<NodeId>()
        var asked = nodes + missing
        var batches = 0
        while (asked.isNotEmpty()) {
            val batch = cloak.server.nodes.get(bob.id, asked)
            batches += 1
            assertWithinBudget(batch.items.flatMap { it.sections })
            assertTrue(batch.unreadNodeIds.size < asked.size)
            assertEquals(asked.toSet(), (batch.items.map { it.nodeId } + batch.missingNodeIds + batch.unreadNodeIds).toSet())
            batch.items.forEach { item ->
                read += item.sections
                var cursor = item.nextCursor
                while (cursor != null) {
                    val page = cloak.server.nodes.get(bob.id, item.nodeId, cursor)
                    assertWithinBudget(page.sections)
                    read += page.sections
                    cursor = page.nextCursor
                }
            }
            missed += batch.missingNodeIds
            asked = batch.unreadNodeIds
        }

        assertTrue(batches >= 2)
        assertEquals(missing.toSet(), missed)
        assertEquals(written.size, read.size)
        assertEquals(written.map { it.section }.toSet(), read.map { it.section }.toSet())
    }

    @Test
    fun `the change feed ends a page at the budget and covers every change once`() {
        val node = cloak.node(alice, vault)
        val written = (1..20).map { cloak.write(alice, vault, node, "large_$it", blocks = LARGEST_BLOCKS) } +
            cloak.write(alice, vault, node, "small")

        val pages = generateSequence(cloak.server.sections.list(alice.id, vault, limit = PageRequest.MAX_LIMIT)) { page ->
            page.takeIf { it.throughChangeSeq < it.lastChangeSeq }?.let {
                cloak.server.sections.list(alice.id, vault, afterChange = it.throughChangeSeq, limit = PageRequest.MAX_LIMIT)
            }
        }.toList()

        assertTrue(pages.size >= 3)
        pages.forEach { page ->
            assertWithinBudget(page.items)
            assertEquals(page.items.last().changeSeq, page.throughChangeSeq)
        }
        assertEquals(written.map { it.changeSeq }, pages.flatMap { page -> page.items.map { it.changeSeq } })
    }

    /** Asserts that one response's sections are whole, at least one, and within the budget. */
    private fun assertWithinBudget(sections: List<SectionWrite>) {
        assertTrue(sections.isNotEmpty())
        assertTrue(sections.size <= PageRequest.MAX_LIMIT)
        assertTrue(sections.sumOf { it.input.ciphertext?.size ?: 0 } <= Limits.MAX_PAGE_BYTES)
    }

    private companion object {
        /** Padding blocks of the largest section: 41 + 256 × 4095 bytes, just under 1 MiB. */
        const val LARGEST_BLOCKS = 4_095

        /** The order a node read returns sections in: by vault, then section name. */
        val NODE_ORDER: Comparator<SectionRef> = compareBy<SectionRef>({ it.vaultId.value.toString() }, { it.sectionName.value })
    }
}
