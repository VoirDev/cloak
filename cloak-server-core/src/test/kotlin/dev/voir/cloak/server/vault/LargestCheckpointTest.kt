package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.protocol.Merkle
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.uuid.Uuid

/**
 * Taking access away must always be possible: a checkpoint over a vault at its section limit is
 * built, stored, read back and served within the server's default database budget.
 */
class LargestCheckpointTest {
    private val cloak = CloakFixture(CloakSettings.defaults())

    @Test
    fun `a vault at its section limit rotates, twice, within the default statement budget`() {
        val alice = cloak.user()
        val vault = cloak.createVault(alice)
        val count = Limits.MAX_SECTIONS_PER_VAULT
        // Writing 100 000 signed sections through the API would take minutes and test nothing the
        // section tests do not; the checkpoint reads only the latest writes' columns, so they are
        // stored directly, as a full vault would hold them.
        cloak.sql(
            """
            insert into cloak.sections (vault_id, node_id, section_name, node_type, home_vault_id, owner_user_id, node_key, vault_key_version, data_version,
                deleted, log_seq, log_head_hash, previous_write_hash, writer_user_id, writer_key_version, ciphertext,
                ciphertext_hash, signature, write_hash, change_seq, written_at)
            select '${vault.value}', md5(i::text)::uuid, 'general', 'compute.vps', '${vault.value}', '${alice.id.value}', i::text, 1, 1, false, 1,
                decode(repeat('aa', 32), 'hex'), null, '${alice.id.value}', 1, decode('01' || repeat('aa', 296), 'hex'),
                decode(repeat('aa', 32), 'hex'), decode('01' || repeat('aa', 64), 'hex'), sha256(int8send(i)), i, now()
            from generate_series(1, $count) as i;
            update cloak.vaults set change_seq = $count, live_section_count = $count, stored_section_count = $count where id = '${vault.value}';
            """.trimIndent(),
        )
        val leaves = cloak.dataSource.connection.use { connection ->
            connection.createStatement().use { statement ->
                val rows = statement.executeQuery("select node_id, write_hash from cloak.sections where vault_id = '${vault.value}'")
                buildList {
                    while (rows.next()) {
                        add(
                            CheckpointLeaf(
                                NodeId(Uuid.parse(rows.getString(1))),
                                SectionName("general"),
                                1,
                                rows.getBytes(2).toByteString(),
                            ),
                        )
                    }
                }
            }
        }.sortedWith(Merkle.sectionOrder)
        val root = Merkle.root(leaves)

        cloak.rotate(alice, vault, recipients = listOf(alice to 1), checkpoint = root)
        cloak.rotate(alice, vault, recipients = listOf(alice to 1), checkpoint = root)
        val seq = cloak.vault(alice, vault).logSeq
        val pages = generateSequence(cloak.server.vaults.checkpointLeaves(alice.id, vault, seq)) { page ->
            page.nextCursor?.let { cloak.server.vaults.checkpointLeaves(alice.id, vault, seq, cursor = it) }
        }.toList()

        assertEquals(count, pages.first().size)
        assertEquals(leaves, pages.flatMap { it.leaves })
        assertEquals(count.toLong(), cloak.number("select count(*) from cloak.checkpoint_leaves"))
    }
}
