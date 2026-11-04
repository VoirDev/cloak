package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.CheckpointProofQuery
import dev.voir.cloak.server.vault.domain.LeftOutWrite
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull

/**
 * Checkpoints stored as spans of leaves: whatever happened between checkpoints, every checkpoint
 * reads back, in pages and in proofs, exactly as the latest writes stood when it was signed.
 */
class CheckpointSpansTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val vault: VaultId = cloak.createVault(alice)

    @Test
    fun `every checkpoint of a random history reads back as the latest writes it was signed over`() {
        val random = Random(20_261_106)
        val names = listOf("general", "secrets", "billing")
        val sections = cloak.writeMany(alice, vault, 40).map { it to "general" }.toMutableList()
        val deleted = mutableSetOf<Pair<NodeId, String>>()
        // Every checkpoint signed so far with the leaves computed independently of the spans.
        val history = mutableListOf<Pair<Long, List<CheckpointLeaf>>>()

        repeat(30) {
            repeat(random.nextInt(0, 8)) {
                when (random.nextInt(4)) {
                    // A new section.
                    0 -> cloak.node(alice, vault).let { node ->
                        val name = names.random(random)
                        cloak.write(alice, vault, node, name)
                        sections += node to name
                    }
                    // A deletion, which no checkpoint holds: the section is simply absent.
                    1 -> (sections - deleted).random(random).let { section ->
                        cloak.write(alice, vault, section.first, section.second, deleted = true)
                        deleted += section
                    }
                    // A new write of an existing section, deleted or not.
                    else -> sections.random(random).let { section ->
                        cloak.write(alice, vault, section.first, section.second)
                        deleted -= section
                    }
                }
            }
            val latest = cloak.leaves(alice, vault)
            // Leave out a few writes now and then, so later checkpoints include them again.
            val leftOut = latest.shuffled(random).take(if (random.nextInt(3) == 0) random.nextInt(1, 4) else 0)
                .map { LeftOutWrite(it.nodeId, it.sectionName, it.writeHash) }
            cloak.rotate(alice, vault, recipients = listOf(alice to 1), leftOut = leftOut)
            val excluded = leftOut.map { it.nodeId to it.sectionName }.toSet()
            history += cloak.vault(alice, vault).logSeq to latest.filterNot { (it.nodeId to it.sectionName) in excluded }
            kotlin.test.assertTrue(latest.none { (it.nodeId to it.sectionName.value) in deleted }, "a deletion became a leaf")

            history.forEach { (seq, expected) ->
                assertEquals(expected, readAll(seq), "checkpoint $seq")
                assertEquals(root(seq), Merkle.root(expected), "root of checkpoint $seq")
            }
            val (seq, expected) = history.random(random)
            val asked = sections.shuffled(random).take(20)
            val proofs = cloak.server.vaults.checkpointProofs(alice.id, vault, asked.map { (node, name) -> CheckpointProofQuery(seq, node, SectionName(name)) })
            asked.zip(proofs).forEach { (section, proof) ->
                val leaf = expected.firstOrNull { it.nodeId == section.first && it.sectionName.value == section.second }
                assertEquals(leaf, proof.inclusion?.leaf, "proof of $section in checkpoint $seq")
            }
        }
    }

    @Test
    fun `checkpoints that change nothing store nothing, and a change stores one span`() {
        cloak.writeMany(alice, vault, 200)
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        val rows = spans()

        repeat(10) { cloak.rotate(alice, vault, recipients = listOf(alice to 1)) }
        val (node, name) = cloak.leaves(alice, vault).first().let { it.nodeId to it.sectionName.value }
        cloak.write(alice, vault, node, name)
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))

        assertEquals(200, rows)
        assertEquals(201, spans())
        assertEquals(cloak.leaves(alice, vault), readAll(cloak.vault(alice, vault).logSeq))
    }

    @Test
    fun `a checkpoint whose stored leaves do not read back as signed is never committed`() {
        cloak.writeMany(alice, vault, 5)
        val head = cloak.vault(alice, vault)
        // Stands in for a bug of the span bookkeeping: every stored leaf is altered on its way in.
        cloak.sql(
            """
            create function cloak.corrupt_leaf() returns trigger language plpgsql as
            $$ begin new.data_version := new.data_version + 1; return new; end $$;
            create trigger corrupt_leaf before insert on cloak.checkpoint_leaves
            for each row execute function cloak.corrupt_leaf();
            """.trimIndent(),
        )

        assertFails { cloak.rotate(alice, vault, recipients = listOf(alice to 1)) }

        assertEquals(head, cloak.vault(alice, vault))
        assertEquals(0, spans())
    }

    /** Reads a checkpoint's leaves page by page. */
    private fun readAll(seq: Long): List<CheckpointLeaf> =
        generateSequence(cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, limit = 7)) { page ->
            page.nextCursor?.let { cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, cursor = it, limit = 7) }
        }.flatMap { page ->
            assertEquals(cloak.number("select checkpoint_size from cloak.vault_log where seq = $seq and vault_id = '${vault.value}'").toInt(), page.size)
            page.leaves
        }.toList()

    /** The checkpoint log entry [seq] carries. */
    private fun root(seq: Long): ByteString =
        assertNotNull(cloak.server.vaults.log(alice.id, vault, afterSeq = seq - 1, limit = 1).items.single().input.checkpoint)

    /** Rows of the span table. */
    private fun spans(): Long = cloak.number("select count(*) from cloak.checkpoint_leaves")
}
