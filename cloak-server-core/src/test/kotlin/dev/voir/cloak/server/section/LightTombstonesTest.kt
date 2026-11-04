package dev.voir.cloak.server.section

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.LeftOutWrite
import dev.voir.cloak.server.vault.domain.VaultId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.uuid.Uuid

/**
 * Deleted sections stay stored without content, so the next write chains to them, but are never a
 * checkpoint leaf and count only against the stored limit (`PROTOCOL.md` §7.5, §13).
 */
class LightTombstonesTest {
    private val cloak = CloakFixture(CloakSettings.builder().maxStoredSectionsPerVault(Limits.MAX_SECTIONS_PER_VAULT).build())
    private val alice: TestClient = cloak.user()
    private val vault: VaultId = cloak.createVault(alice)
    private val kept = cloak.node(alice, vault)
    private val gone = cloak.node(alice, vault)

    @Test
    fun `a checkpoint holds live sections only, and one over a deletion is refused`() {
        cloak.write(alice, vault, kept, "general")
        cloak.write(alice, vault, gone, "general")
        val deletion = cloak.write(alice, vault, gone, "general", deleted = true)
        val withDeletion = (cloak.leaves(alice, vault) + CheckpointLeaf(gone, deletion.section.sectionName, 2, deletion.writeHash))
            .sortedWith(Merkle.sectionOrder)

        assertCloakError(CloakErrorCode.CHECKPOINT_CONFLICT) {
            cloak.rotate(alice, vault, recipients = listOf(alice to 1), checkpoint = Merkle.root(withDeletion))
        }
        assertCloakError(CloakErrorCode.CHECKPOINT_CONFLICT) {
            cloak.rotate(alice, vault, recipients = listOf(alice to 1), leftOut = listOf(LeftOutWrite(gone, deletion.section.sectionName, deletion.writeHash)))
        }
        val rotated = cloak.rotate(alice, vault, recipients = listOf(alice to 1))

        val leaves = cloak.server.vaults.checkpointLeaves(alice.id, vault, rotated.logSeq).leaves
        assertEquals(listOf(kept), leaves.map { it.nodeId })
        // The deletion is still stored, so the next write of the section chains to it.
        assertEquals(3, cloak.write(alice, vault, gone, "general").input.dataVersion)
    }

    @Test
    fun `live and stored counts follow creations, deletions and rewrites`() {
        cloak.write(alice, vault, kept, "general")
        cloak.write(alice, vault, gone, "general")
        cloak.write(alice, vault, gone, "general", deleted = true)
        assertEquals(1L to 2L, counts())

        cloak.write(alice, vault, gone, "general")
        assertEquals(2L to 2L, counts())
        cloak.write(alice, vault, gone, "general", deleted = true)
        cloak.write(alice, vault, kept, "general", deleted = true)
        assertEquals(0L to 2L, counts())
    }

    @Test
    fun `the stored limit refuses new names only, and the live limit refuses what would make one live`() {
        cloak.write(alice, vault, gone, "general")
        cloak.write(alice, vault, gone, "general", deleted = true)
        cloak.sql("update cloak.vaults set stored_section_count = ${Limits.MAX_SECTIONS_PER_VAULT} where id = '${vault.value}'")

        val stored = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, vault, cloak.node(alice, vault), "general") }
        assertEquals("max_stored_sections", stored.fieldErrors.single().code)
        // An existing name is no new stored section.
        cloak.write(alice, vault, gone, "general")
        cloak.write(alice, vault, gone, "general", deleted = true)

        cloak.sql("update cloak.vaults set live_section_count = ${Limits.MAX_SECTIONS_PER_VAULT} where id = '${vault.value}'")
        val live = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(alice, vault, gone, "general") }
        assertEquals("max_sections", live.fieldErrors.single().code)
    }

    /** The vault's live and stored section counts. */
    private fun counts(): Pair<Long, Long> =
        cloak.number("select live_section_count from cloak.vaults where id = '${vault.value}'") to
            cloak.number("select stored_section_count from cloak.vaults where id = '${vault.value}'")
}
