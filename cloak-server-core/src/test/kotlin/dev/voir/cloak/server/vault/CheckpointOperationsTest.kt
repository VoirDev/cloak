package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.CheckpointProof
import dev.voir.cloak.server.vault.domain.CheckpointProofQuery
import dev.voir.cloak.server.vault.domain.LeafProof
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlinx.io.bytestring.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/** Proofs of what checkpoints hold, and checkpoints' leaf lists (`PROTOCOL.md` §7.5). */
class CheckpointOperationsTest {
    private val cloak = CloakFixture()
    private val alice = cloak.user()
    private val bob = cloak.user()
    private val vault = cloak.createVault(alice)
    private val general = SectionName("general")

    @Test
    fun `proves sections against several checkpoints in one request`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        val early = (1..3).map { cloak.node(alice, vault).also { node -> cloak.write(bob, vault, node, "general") } }
        cloak.setRole(alice, vault, bob, Role.VIEWER, withCheckpoint = true)
        val first = cloak.vault(alice, vault).logSeq
        val late = cloak.node(alice, vault).also { cloak.write(alice, vault, it, "general") }
        cloak.rotate(alice, vault, recipients = listOf(alice to 1, bob to 1))
        val second = cloak.vault(alice, vault).logSeq
        val lowest = NodeId(Uuid.parse("00000000-0000-0000-0000-000000000000"))
        val highest = NodeId(Uuid.parse("ffffffff-ffff-ffff-ffff-ffffffffffff"))

        val queries = listOf(
            CheckpointProofQuery(first, early[1], general),
            CheckpointProofQuery(second, late, general),
            CheckpointProofQuery(first, late, general),
            CheckpointProofQuery(second, lowest, general),
            CheckpointProofQuery(second, highest, general),
            CheckpointProofQuery(second, early[0], SectionName("zzz")),
        )
        val proofs = cloak.server.vaults.checkpointProofs(bob.id, vault, queries)

        assertEquals(queries.map { it.checkpointSeq }, proofs.map { it.checkpointSeq })
        assertEquals(3L, proofs[0].size)
        assertEquals(4L, proofs[1].size)
        assertIncluded(proofs[0], early[1], root(first))
        assertIncluded(proofs[1], late, root(second))
        assertAbsent(proofs[2], late, root(first))
        val belowAll = assertAbsent(proofs[3], lowest, root(second))
        assertNull(belowAll.before)
        assertEquals(0L, belowAll.after?.index)
        val aboveAll = assertAbsent(proofs[4], highest, root(second))
        assertNull(aboveAll.after)
        assertEquals(3L, aboveAll.before?.index)
        assertAbsent(proofs[5], early[0], root(second), SectionName("zzz"))
    }

    @Test
    fun `refuses an empty, oversized or repeating proof batch`() {
        cloak.write(alice, vault, cloak.node(alice, vault), "general")
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        val seq = cloak.vault(alice, vault).logSeq
        val query = CheckpointProofQuery(seq, NodeId(Uuid.random()), general)

        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.vaults.checkpointProofs(alice.id, vault, emptyList()) }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.vaults.checkpointProofs(alice.id, vault, List(101) { query.copy(nodeId = NodeId(Uuid.random())) })
        }
        val repeated = assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.vaults.checkpointProofs(alice.id, vault, listOf(query, query))
        }
        assertEquals("/items/1", repeated.fieldErrors.single().pointer)
    }

    @Test
    fun `answers not_found for an entry without a checkpoint, an unknown entry and a non-member`() {
        cloak.write(alice, vault, cloak.node(alice, vault), "general")
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        val seq = cloak.vault(alice, vault).logSeq
        val good = CheckpointProofQuery(seq, NodeId(Uuid.random()), general)

        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.checkpointProofs(alice.id, vault, listOf(good, good.copy(checkpointSeq = 1))) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.checkpointProofs(alice.id, vault, listOf(good.copy(checkpointSeq = 999))) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.checkpointProofs(bob.id, vault, listOf(good)) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.checkpointLeaves(alice.id, vault, 1) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.checkpointLeaves(alice.id, vault, 999) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.vaults.checkpointLeaves(bob.id, vault, seq) }
    }

    @Test
    fun `lists a checkpoint's leaves page by page, and they rebuild the signed root`() {
        cloak.writeMany(alice, vault, 7)
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        val seq = cloak.vault(alice, vault).logSeq

        val pages = generateSequence(cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, limit = 3)) { page ->
            page.nextCursor?.let { cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, cursor = it, limit = 3) }
        }.toList()

        assertEquals(listOf(3, 3, 1), pages.map { it.leaves.size })
        assertEquals(listOf(7, 7, 7), pages.map { it.size })
        assertNull(pages.last().nextCursor)
        val leaves = pages.flatMap { it.leaves }
        assertEquals(leaves.sortedWith(Merkle.sectionOrder), leaves)
        assertEquals(root(seq), Merkle.root(leaves))
        assertEquals(cloak.leaves(alice, vault), leaves)
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, limit = 1_001) }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, cursor = "nope!") }
        // A cursor names its checkpoint, so it cannot continue another one.
        val first = assertNotNull(pages.first().nextCursor)
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.vaults.checkpointLeaves(alice.id, vault, cloak.vault(alice, vault).logSeq, cursor = first)
        }
    }

    @Test
    fun `an empty checkpoint has no leaves and the root of nothing`() {
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        val seq = cloak.vault(alice, vault).logSeq

        val page = cloak.server.vaults.checkpointLeaves(alice.id, vault, seq)
        val proof = cloak.server.vaults.checkpointProofs(alice.id, vault, listOf(CheckpointProofQuery(seq, NodeId(Uuid.random()), general))).single()

        assertEquals(0, page.size)
        assertEquals(root(seq), Merkle.root(emptyList()))
        assertEquals(CheckpointProof(seq, 0, null, null, null), proof)
    }

    @Test
    fun `a vault of thousands of sections checkpoints, proves and lists correctly`() {
        val nodes = cloak.writeMany(alice, vault, 2_500)
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        val seq = cloak.vault(alice, vault).logSeq
        val root = root(seq)

        val sample = nodes.shuffled().take(100)
        val proofs = cloak.server.vaults.checkpointProofs(alice.id, vault, sample.map { CheckpointProofQuery(seq, it, general) })
        sample.zip(proofs).forEach { (node, proof) -> assertIncluded(proof, node, root) }

        val leaves = generateSequence(cloak.server.vaults.checkpointLeaves(alice.id, vault, seq)) { page ->
            page.nextCursor?.let { cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, cursor = it) }
        }.toList()
        assertEquals(listOf(1_000, 1_000, 500), leaves.map { it.leaves.size })
        assertEquals(root, Merkle.root(leaves.flatMap { it.leaves }))
        assertEquals(2_500, cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, limit = 1).size)
    }

    /** The checkpoint log entry [seq] carries. */
    private fun root(seq: Long, vaultId: VaultId = vault): ByteString =
        assertNotNull(cloak.server.vaults.log(alice.id, vaultId, afterSeq = seq - 1, limit = 1).items.single().input.checkpoint)

    /** Asserts [proof] shows [node]'s section in the checkpoint with [root]. */
    private fun assertIncluded(proof: CheckpointProof, node: NodeId, root: ByteString) {
        val inclusion = assertNotNull(proof.inclusion, "inclusion of $node")
        assertEquals(node, inclusion.leaf.nodeId)
        assertEquals(general, inclusion.leaf.sectionName)
        assertNull(proof.before)
        assertNull(proof.after)
        assertProves(inclusion, proof.size, root)
    }

    /** Asserts [proof] shows the section absent: verified neighbours around where it would be. */
    private fun assertAbsent(proof: CheckpointProof, node: NodeId, root: ByteString, name: SectionName = general): CheckpointProof {
        assertNull(proof.inclusion)
        val probe = CheckpointLeaf(node, name, 1, ByteString(ByteArray(32)))
        proof.before?.let {
            assertProves(it, proof.size, root)
            assertTrue(Merkle.sectionOrder.compare(it.leaf, probe) < 0)
        }
        proof.after?.let {
            assertProves(it, proof.size, root)
            assertTrue(Merkle.sectionOrder.compare(it.leaf, probe) > 0)
        }
        assertEquals((proof.before?.index ?: -1) + 1, proof.after?.index ?: proof.size)
        return proof
    }

    /** Asserts a leaf's audit path reaches [root]. */
    private fun assertProves(leaf: LeafProof, size: Long, root: ByteString) {
        assertTrue(Merkle.verifyInclusion(leaf.index, size, Merkle.leafHash(leaf.leaf), leaf.path, root))
    }
}
