package dev.voir.cloak.server.section

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.SectionWriteFields
import dev.voir.cloak.server.protocol.sha256
import dev.voir.cloak.server.section.domain.BatchWriteItem
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeKey
import dev.voir.cloak.server.section.domain.NodeOrigin
import dev.voir.cloak.server.section.domain.SectionHeader
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.vault.domain.Role
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/** Writing, reading, deleting and moving sections; the change feed; node reads; races. */
class SectionOperationsTest {
    private val cloak = CloakFixture()
    private val alice = cloak.user()
    private val bob = cloak.user()
    private val vault = cloak.createVault(alice)
    private val node = cloak.node(alice, vault)

    @Test
    fun `writes chain to each other with increasing versions and change numbers`() {
        val first = cloak.write(alice, vault, node, "general")
        val second = cloak.write(alice, vault, node, "general")

        assertEquals(1, first.input.dataVersion)
        assertEquals(2, second.input.dataVersion)
        assertEquals(first.writeHash, second.input.previousWriteHash)
        assertEquals(listOf(1L, 2L), listOf(first.changeSeq, second.changeSeq))
        assertEquals(second, cloak.server.sections.get(alice.id, SectionRef(vault, node, SectionName("general"))))
    }

    @Test
    fun `refuses a viewer, a stale head, a stale key and a write someone else beat`() {
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        assertCloakError(CloakErrorCode.ROLE_REQUIRED) { cloak.write(bob, vault, node, "general") }

        val ref = SectionRef(vault, node, SectionName("general"))
        val staleHead = cloak.writeInput(alice, vault, node, "general")
        cloak.setRole(alice, vault, bob, Role.EDITOR)
        assertCloakError(CloakErrorCode.STALE_HEAD) { cloak.server.sections.write(alice.id, ref, staleHead) }

        val raced = cloak.writeInput(alice, vault, node, "general")
        cloak.write(bob, vault, node, "general")
        val conflict = assertCloakError(CloakErrorCode.VERSION_CONFLICT) { cloak.server.sections.write(alice.id, ref, raced) }
        assertEquals(1, conflict.currentVersion)

        cloak.rotate(alice, vault, recipients = listOf(alice to 1, bob to 1))
        val oldKey = cloak.writeInput(alice, vault, node, "general").copy(vaultKeyVersion = 1)
        assertCloakError(CloakErrorCode.VAULT_KEY_VERSION_MISMATCH) { cloak.server.sections.write(alice.id, ref, oldKey) }
    }

    @Test
    fun `refuses a forged signature and a node type change`() {
        val ref = SectionRef(vault, node, SectionName("general"))
        val input = cloak.writeInput(alice, vault, node, "general")
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.sections.write(alice.id, ref, input.copy(ciphertext = TestBlobs.ciphertext()))
        }
        cloak.server.sections.write(alice.id, ref, input)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, vault, node, "general", nodeType = "project") }
    }

    @Test
    fun `a deletion keeps the section's versions, and a later write continues them`() {
        cloak.write(alice, vault, node, "general")
        val deleted = cloak.write(alice, vault, node, "general", deleted = true)
        val again = cloak.write(alice, vault, node, "general")

        assertTrue(deleted.input.deleted)
        assertNull(deleted.input.ciphertext)
        assertEquals(3, again.input.dataVersion)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.write(alice, vault, cloak.node(alice, vault), "general", deleted = true) }
    }

    @Test
    fun `the change feed returns only what changed, deletions included`() {
        val other = cloak.node(alice, vault)
        cloak.write(alice, vault, node, "general")
        val since = cloak.write(alice, vault, other, "general").changeSeq
        cloak.write(alice, vault, node, "general", deleted = true)

        val page = cloak.server.sections.list(alice.id, vault, afterChange = since)

        assertEquals(listOf(node), page.items.map { it.section.nodeId })
        assertTrue(page.items.single().input.deleted)
        assertEquals(3, page.lastChangeSeq)
    }

    @Test
    fun `headers list the latest writes without ciphertext, page by page`() {
        val nodes = cloak.writeMany(alice, vault, 5)
        cloak.write(alice, vault, nodes[0], "general", deleted = true)

        val first = cloak.server.sections.headers(alice.id, vault, limit = 4)
        val second = cloak.server.sections.headers(alice.id, vault, afterChange = first.items.last().changeSeq, limit = 4)
        val headers = first.items + second.items
        val writes = cloak.server.sections.list(alice.id, vault).items

        assertEquals(6, first.lastChangeSeq)
        assertEquals(listOf(2L, 3, 4, 5, 6), headers.map { it.changeSeq })
        assertEquals(nodes.drop(1) + nodes[0], headers.map { it.section.nodeId })
        assertEquals(writes.map { it.header }, headers)
        headers.zip(writes).forEach { (header, write) ->
            assertEquals(write.input.ciphertext?.let(::sha256), header.ciphertextHash)
            assertEquals(header.writeHash, sha256(Messages.sectionWrite(header.fields())))
        }
        assertNull(headers.last().ciphertextHash)
        assertTrue(headers.last().deleted)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.sections.headers(alice.id, vault, limit = 1_001) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.sections.headers(bob.id, vault) }
    }

    @Test
    fun `a vault refuses a new section past its limit, but its sections can still change`() {
        cloak.write(alice, vault, node, "general")
        cloak.sql(
            "update cloak.vaults set live_section_count = ${Limits.MAX_SECTIONS_PER_VAULT - 1}, " +
                "stored_section_count = ${Limits.MAX_SECTIONS_PER_VAULT - 1} where id = '${vault.value}'",
        )
        val last = cloak.node(alice, vault)
        cloak.write(alice, vault, last, "general")

        val refused = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, vault, cloak.node(alice, vault), "general") }
        assertEquals("max_sections", refused.fieldErrors.single().code)
        val batch = assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.sections.batchWrite(
                alice.id,
                listOf(
                    BatchWriteItem(SectionRef(vault, node, SectionName("general")), cloak.writeInput(alice, vault, node, "general")),
                    BatchWriteItem(SectionRef(vault, node, SectionName("billing")), cloak.writeInput(alice, vault, node, "billing")),
                ),
            )
        }
        assertEquals("/items/1", batch.fieldErrors.single().pointer)

        cloak.write(alice, vault, node, "general")
        cloak.write(alice, vault, last, "general", deleted = true)
        cloak.write(alice, vault, last, "general")
        assertEquals(3, cloak.server.sections.get(alice.id, SectionRef(vault, last, SectionName("general"))).input.dataVersion)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, vault, cloak.node(alice, vault), "general") }
        val other = cloak.createVault(alice)
        cloak.share(alice, other, node)
        cloak.write(alice, other, node, "general")
    }

    @Test
    fun `a batch moves a section between vaults, or does nothing when one write fails`() {
        val target = cloak.createVault(alice)
        cloak.share(alice, target, node, "secrets")
        cloak.write(alice, vault, node, "secrets")
        val move = listOf(
            BatchWriteItem(SectionRef(vault, node, SectionName("secrets")), cloak.writeInput(alice, vault, node, "secrets", deleted = true)),
            BatchWriteItem(SectionRef(target, node, SectionName("secrets")), cloak.writeInput(alice, target, node, "secrets")),
        )
        val broken = listOf(move[0], move[1].copy(input = move[1].input.copy(signature = TestBlobs.blob(65))))

        assertCloakError(CloakErrorCode.BAD_SIGNATURE) { cloak.server.sections.batchWrite(alice.id, broken) }
        assertFalse(cloak.server.sections.get(alice.id, move[0].section).input.deleted)

        cloak.server.sections.batchWrite(alice.id, move)
        assertTrue(cloak.server.sections.get(alice.id, move[0].section).input.deleted)
        assertEquals(1, cloak.server.sections.get(alice.id, move[1].section).input.dataVersion)
    }

    @Test
    fun `a node shows each reader only the sections in their vaults`() {
        val shared = cloak.createVault(alice)
        cloak.addMember(alice, shared, bob, Role.VIEWER)
        cloak.server.members.accept(bob.id, shared)
        cloak.share(alice, shared, node, "general")
        cloak.write(alice, vault, node, "secrets")
        cloak.write(alice, shared, node, "general")

        assertEquals(2, cloak.server.nodes.get(alice.id, node).sections.size)
        assertEquals(listOf(SectionName("general")), cloak.server.nodes.get(bob.id, node).sections.map { it.section.sectionName })
        assertEquals(Role.VIEWER, cloak.server.access.role(bob.hostUserId.value, shared.value))
        assertNull(cloak.server.access.role(bob.hostUserId.value, vault.value))
        val missing = NodeId(Uuid.random())
        assertEquals(listOf(missing), cloak.server.nodes.get(bob.id, listOf(node, missing)).missingNodeIds)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.sections.get(bob.id, SectionRef(vault, node, SectionName("secrets"))) }
    }

    @Test
    fun `concurrent writes of one section store exactly one, and change numbers stay unique`() {
        val inputs = (1..8).map { cloak.writeInput(alice, vault, node, "general") }
        val ref = SectionRef(vault, node, SectionName("general"))
        val outcomes = race(inputs.map { input -> { cloak.server.sections.write(alice.id, ref, input) } })

        assertEquals(1, outcomes.count { it == null })
        assertTrue(outcomes.filterNotNull().all { it == CloakErrorCode.VERSION_CONFLICT })

        val others = (1..8).map { cloak.node(alice, vault) }
        race(others.map { id -> { retry { cloak.write(alice, vault, id, "general") } } })
        val changes = cloak.leaves(alice, vault).size
        assertEquals(9, changes)
        assertEquals(9, cloak.server.sections.list(alice.id, vault, limit = 100).items.map { it.changeSeq }.toSet().size)
    }

    @Test
    fun `a rotation and a write that race never leave a write outside the checkpoint unnoticed`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.write(bob, vault, node, "general")
        val write = cloak.writeInput(bob, vault, node, "general")
        val checkpoint = cloak.checkpoint(alice, vault)

        val outcomes = race(
            listOf(
                { cloak.server.sections.write(bob.id, SectionRef(vault, node, SectionName("general")), write) },
                { cloak.rotate(alice, vault, removed = listOf(bob), recipients = listOf(alice to 1), checkpoint = checkpoint) },
            ),
        )

        // Either the write lands first and the rotation's checkpoint no longer matches, or the
        // rotation lands first and the write's head is stale. Never both.
        assertTrue(outcomes == listOf(null, CloakErrorCode.CHECKPOINT_CONFLICT) || outcomes == listOf(CloakErrorCode.NOT_FOUND, null))
    }

    /** Runs tasks at once; returns each one's error code, or `null` when it succeeded. */
    private fun race(tasks: List<() -> Any>): List<CloakErrorCode?> {
        val pool = Executors.newFixedThreadPool(tasks.size)
        val start = CountDownLatch(1)
        val futures = tasks.map { task ->
            pool.submit<CloakErrorCode?> {
                start.await()
                try {
                    task()
                    null
                } catch (error: CloakException) {
                    error.code
                }
            }
        }
        start.countDown()
        val outcomes = futures.map { it.get(60, TimeUnit.SECONDS) }
        pool.shutdown()
        return outcomes
    }

    /** Retries a write that lost a race for the vault's head, as a client would. */
    private fun retry(block: () -> Any): Any {
        repeat(20) {
            try {
                return block()
            } catch (error: CloakException) {
                if (error.code != CloakErrorCode.STALE_HEAD) throw error
            }
        }
        error("The write never landed")
    }

    /** The signed fields of a header; the ciphertext's digest stands in for the ciphertext. */
    private fun SectionHeader.fields(): SectionWriteFields =
        SectionWriteFields(
            vaultId = section.vaultId,
            nodeId = section.nodeId,
            nodeType = nodeType,
            origin = NodeOrigin(ownerUserId, homeVaultId, NodeKey(nodeKey)),
            sectionName = section.sectionName,
            vaultKeyVersion = vaultKeyVersion,
            dataVersion = dataVersion,
            deleted = deleted,
            logSeq = logSeq,
            logHeadHash = logHeadHash,
            previousWriteHash = previousWriteHash,
            writerUserId = writerUserId,
            writerKeyVersion = writerKeyVersion,
            ciphertextHash = ciphertextHash,
        )
}
