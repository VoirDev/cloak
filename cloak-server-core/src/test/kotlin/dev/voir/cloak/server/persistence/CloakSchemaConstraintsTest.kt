package dev.voir.cloak.server.persistence

import dev.voir.cloak.server.testing.TestPostgres
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.TestInstance
import java.sql.Connection
import java.sql.SQLException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Checks that every named constraint of the `cloak` schema rejects the row it exists for. Each
 * case inserts one valid row with a single column changed, inside a transaction that is rolled
 * back, against rows seeded once.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloakSchemaConstraintsTest {
    @BeforeAll
    fun seed() {
        TestPostgres.freshDataSource()
        inTransaction(commit = true) { connection ->
            connection.run(identity(ALICE))
            connection.run(identityKey(ALICE, 1, signingByte = "a1"))
            connection.run(identity(BOB))
            connection.run(identityKey(BOB, 1, signingByte = "b1"))
            connection.run(vault(VAULT))
            connection.run(vault(OTHER_VAULT_LOG))
            connection.run(vaultKey(VAULT, 1))
            connection.run(member(VAULT, ALICE))
            connection.run(log(VAULT, 1))
            connection.run(log(VAULT, 9, *ROLE_SET))
            connection.run(section(VAULT, "general"))
            connection.run(checkpointLeaf(VAULT, 1))
            connection.run(pauseRequest(VAULT, ALICE))
            connection.run(removal(VAULT, 5))
            connection.run(node(VAULT))
            connection.run(share(VAULT))
            connection.run(shareName(VAULT, "general"))
        }
    }

    @Test
    fun `valid rows of every table insert`() {
        inTransaction { connection ->
            connection.run(identity(CAROL))
            connection.run(identityKey(CAROL, 1, signingByte = "c1"))
            connection.run(identityKey(ALICE, 2, signingByte = "a2"))
            connection.run(vaultKey(VAULT, 2))
            connection.run(member(VAULT, BOB, "role" to "'viewer'", "key_envelope" to "null", "envelope_key_version" to "null", "accepted" to "false", "added_by_user_id" to "'$ALICE'"))
            connection.run(log(VAULT, 2, *ROLE_SET))
            connection.run(checkpointLeaf(VAULT, 2, "section_name" to "'other'"))
            connection.run(checkpointLeaf(VAULT, 1, "section_name" to "'third'", "until_seq" to "2"))
            connection.run(checkpointLeaf(VAULT, 2, "section_name" to "'third'"))
            connection.run(identity(CAROL.replace("2a", "3b"), *DELETED))
            connection.run(log(VAULT, 3, *ROLE_SET, "checkpoint" to bytes(32), "checkpoint_size" to "0"))
            connection.run(section(VAULT, "billing", "deleted" to "true", "ciphertext" to "null", "ciphertext_hash" to "null", "data_version" to "2", "previous_write_hash" to bytes(32), "change_seq" to "2"))
            connection.run(vault(OTHER_VAULT, "pause_user_id" to "'$ALICE'", "pause_by_admin" to "true", "pause_until" to NOW))
            connection.run(pauseRequest(VAULT, BOB))
            connection.run(removal(VAULT, 6, "section_name" to "'other'"))
            connection.run(insert("accepted_inviters", mapOf("user_id" to "'$BOB'", "inviter_user_id" to "'$ALICE'", "accepted_at" to NOW), emptyArray()))
            connection.run(node(VAULT, "node_id" to "'$OTHER_NODE'"))
            connection.run(shareName(VAULT, "billing"))
            connection.run(log(VAULT, 4, "kind" to "'node_created'", "subject_user_id" to "null", "role" to "null", "subject_keys" to "null", "subject_key_version" to "null", "node_id" to "'$NODE'", "node_key" to "'server-1'"))
            connection.run(log(VAULT, 5, "kind" to "'node_shared'", "subject_user_id" to "null", "role" to "null", "subject_keys" to "null", "subject_key_version" to "null", "node_id" to "'$NODE'", "home_vault_id" to "'$OTHER_VAULT'", "node_key" to "'server-1'", "sections" to "'*'"))
            connection.run(log(VAULT, 6, "kind" to "'node_unshared'", "subject_user_id" to "null", "role" to "null", "subject_keys" to "null", "subject_key_version" to "null", "node_id" to "'$NODE'", "sections" to "'*'"))
            connection.run(log(VAULT, 7, "kind" to "'vault_deleted'", "subject_user_id" to "null", "role" to "null", "subject_keys" to "null", "subject_key_version" to "null"))
            connection.run("update cloak.vaults set deleted_at = $NOW where id = '$VAULT'")
        }
    }

    @TestFactory
    fun `each constraint rejects its invalid row`(): List<DynamicTest> = listOf(
        "pk_identities" to identity(ALICE),
        "uq_identities__host_user_id" to identity(CAROL, "host_user_id" to "'host-$ALICE'"),
        "ck_identities__host_user_id_length" to identity(CAROL, "host_user_id" to "''"),
        "ck_identities__key_version" to identity(CAROL, "key_version" to "0"),
        "ck_identities__kdf_salt_length" to identity(CAROL, "kdf_salt" to bytes(15)),
        "ck_identities__kdf_memory_kib" to identity(CAROL, "kdf_memory_kib" to "1048577"),
        "ck_identities__kdf_iterations" to identity(CAROL, "kdf_iterations" to "1"),
        "ck_identities__kdf_parallelism" to identity(CAROL, "kdf_parallelism" to "2"),
        "ck_identities__credentials_version" to identity(CAROL, "credentials_version" to "0"),
        "ck_identities__updated_after_created" to identity(CAROL, "updated_at" to "'2026-01-01T00:00:00Z'"),
        "ck_identities__deleted" to identity(CAROL, "deleted_at" to NOW),
        "ck_identities__deleted" to identity(CAROL, "private_key_bundle" to "null"),
        "ck_identities__deleted" to identity(CAROL, *DELETED, "kdf_salt" to bytes(16)),
        "pk_identity_keys" to identityKey(ALICE, 1, signingByte = "a3"),
        "fk_identity_keys__user_id__identities" to identityKey(CAROL, 1, signingByte = "c2"),
        "uq_identity_keys__signing_public_key" to identityKey(ALICE, 2, signingByte = "a1"),
        "ck_identity_keys__crypto_suite" to identityKey(ALICE, 2, signingByte = "a5", "crypto_suite" to "2"),
        "ck_identity_keys__encryption_public_key_length" to identityKey(ALICE, 2, signingByte = "a6", "encryption_public_key" to bytes(31)),
        "ck_identity_keys__signing_public_key_length" to identityKey(ALICE, 2, signingByte = "a7", "signing_public_key" to bytes(33)),
        "ck_identity_keys__recovery_signing_public_key_length" to identityKey(ALICE, 2, signingByte = "a8", "recovery_signing_public_key" to bytes(31)),
        "ck_identity_keys__keys_digest_length" to identityKey(ALICE, 2, signingByte = "a9", "keys_digest" to bytes(31)),
        "ck_identity_keys__signature_length" to identityKey(ALICE, 2, signingByte = "aa", "signature" to bytes(64)),
        "ck_identity_keys__chain" to identityKey(ALICE, 2, signingByte = "ab", "recovery_signature" to "null"),
        "pk_vaults" to vault(VAULT),
        "fk_vaults__created_by_user_id__identities" to vault(OTHER_VAULT, "created_by_user_id" to "'$CAROL'"),
        "ck_vaults__key_version" to vault(OTHER_VAULT, "key_version" to "0"),
        "ck_vaults__log_seq" to vault(OTHER_VAULT, "log_seq" to "0"),
        "ck_vaults__log_head_hash_length" to vault(OTHER_VAULT, "log_head_hash" to bytes(31)),
        "ck_vaults__change_seq" to vault(OTHER_VAULT, "change_seq" to "-1"),
        "ck_vaults__live_section_count" to vault(OTHER_VAULT, "live_section_count" to "-1"),
        "ck_vaults__stored_section_count" to vault(OTHER_VAULT, "live_section_count" to "2", "stored_section_count" to "1"),
        "ck_vaults__pause_complete" to vault(OTHER_VAULT, "pause_user_id" to "'$ALICE'"),
        "pk_vault_keys" to vaultKey(VAULT, 1),
        "fk_vault_keys__vault_id__vaults" to vaultKey(OTHER_VAULT, 1),
        "ck_vault_keys__key_commitment_length" to vaultKey(VAULT, 2, "key_commitment" to bytes(31)),
        "ck_vault_keys__previous_only_after_first" to vaultKey(VAULT, 2, "previous_wrapped_key" to "null"),
        "pk_vault_members" to member(VAULT, ALICE),
        "fk_vault_members__vault_id__vaults" to member(OTHER_VAULT, BOB, "key_envelope" to "null", "envelope_key_version" to "null"),
        "fk_vault_members__user_id_user_key_version__identity_keys" to member(VAULT, BOB, "user_key_version" to "9"),
        "fk_vault_members__vault_id_envelope_key_version__vault_keys" to member(VAULT, BOB, "envelope_key_version" to "9"),
        "ck_vault_members__role" to member(VAULT, BOB, "role" to "'guest'"),
        "ck_vault_members__keys_digest_length" to member(VAULT, BOB, "keys_digest" to bytes(31)),
        "ck_vault_members__envelope_complete" to member(VAULT, BOB, "envelope_key_version" to "null"),
        "pk_vault_log" to log(VAULT, 1),
        "fk_vault_log__vault_id__vaults" to log(OTHER_VAULT, 1),
        "fk_vault_log__author_user_id_author_key_version__identity_keys" to log(VAULT, 2, *ROLE_SET, "author_key_version" to "9"),
        "ck_vault_log__key_version" to log(VAULT, 2, *ROLE_SET, "key_version" to "0"),
        "ck_vault_log__role" to log(VAULT, 2, *ROLE_SET, "role" to "'guest'"),
        "ck_vault_log__signature_length" to log(VAULT, 2, *ROLE_SET, "signature" to bytes(64)),
        "ck_vault_log__entry_hash_length" to log(VAULT, 2, *ROLE_SET, "entry_hash" to bytes(31)),
        "ck_vault_log__subject_keys_complete" to log(VAULT, 2, *ROLE_SET, "subject_key_version" to "null"),
        "ck_vault_log__key_commitment_length" to log(VAULT, 2, "kind" to "'key_rotated'", "subject_user_id" to "null", "role" to "null", "subject_keys" to "null", "subject_key_version" to "null", "key_commitment" to bytes(31), "checkpoint" to bytes(32), "checkpoint_size" to "1"),
        "ck_vault_log__checkpoint_length" to log(VAULT, 2, *ROLE_SET, "checkpoint" to bytes(31), "checkpoint_size" to "1"),
        "ck_vault_log__checkpoint_size" to log(VAULT, 2, *ROLE_SET, "checkpoint" to bytes(32)),
        "ck_vault_log__checkpoint_size" to log(VAULT, 2, *ROLE_SET, "checkpoint_size" to "1"),
        "ck_vault_log__checkpoint_size" to log(VAULT, 2, *ROLE_SET, "checkpoint" to bytes(32), "checkpoint_size" to "-1"),
        "ck_vault_log__kind_shape" to log(VAULT, 2, *ROLE_SET, "role" to "null"),
        "ck_vault_log__kind_shape" to log(OTHER_VAULT_LOG, 1, "role" to "null"),
        "pk_checkpoint_leaves" to checkpointLeaf(VAULT, 1),
        "fk_checkpoint_leaves__vault_id_from_seq__vault_log" to checkpointLeaf(VAULT, 8, "section_name" to "'other'"),
        "fk_checkpoint_leaves__vault_id_until_seq__vault_log" to checkpointLeaf(VAULT, 1, "section_name" to "'other'", "until_seq" to "8"),
        "uq_checkpoint_leaves__vault_id_node_id_section_name__open" to checkpointLeaf(VAULT, 9),
        "ck_checkpoint_leaves__span" to checkpointLeaf(VAULT, 9, "section_name" to "'other'", "until_seq" to "1"),
        "ck_checkpoint_leaves__section_name_format" to checkpointLeaf(VAULT, 1, "section_name" to "'Other'"),
        "ck_checkpoint_leaves__data_version" to checkpointLeaf(VAULT, 1, "section_name" to "'other'", "data_version" to "0"),
        "ck_checkpoint_leaves__write_hash_length" to checkpointLeaf(VAULT, 1, "section_name" to "'other'", "write_hash" to bytes(31)),
        "pk_sections" to section(VAULT, "general", "change_seq" to "5"),
        "fk_sections__vault_id__vaults" to section(OTHER_VAULT, "billing"),
        "fk_sections__vault_id_vault_key_version__vault_keys" to section(VAULT, "billing", "vault_key_version" to "9", "change_seq" to "7"),
        "fk_sections__writer_user_id_writer_key_version__identity_keys" to section(VAULT, "billing", "writer_key_version" to "9", "change_seq" to "7"),
        "uq_sections__vault_id_change_seq" to section(VAULT, "billing", "change_seq" to "1"),
        "ck_sections__section_name_format" to section(VAULT, "Billing"),
        "ck_sections__node_type_format" to section(VAULT, "billing", "node_type" to "'Compute'"),
        "ck_sections__data_version" to section(VAULT, "billing", "data_version" to "0"),
        "ck_sections__log_seq" to section(VAULT, "billing", "log_seq" to "0"),
        "ck_sections__log_head_hash_length" to section(VAULT, "billing", "log_head_hash" to bytes(31)),
        "ck_sections__previous_write_hash" to section(VAULT, "billing", "data_version" to "2", "change_seq" to "7"),
        "ck_sections__deleted_has_no_ciphertext" to section(VAULT, "billing", "deleted" to "true"),
        "ck_sections__ciphertext_size" to section(VAULT, "billing", "ciphertext" to bytes(300)),
        "ck_sections__ciphertext_hash" to section(VAULT, "billing", "ciphertext_hash" to "null"),
        "ck_sections__ciphertext_hash" to section(VAULT, "billing", "ciphertext_hash" to bytes(31)),
        "ck_sections__ciphertext_hash" to section(VAULT, "billing", "deleted" to "true", "ciphertext" to "null", "data_version" to "2", "previous_write_hash" to bytes(32), "change_seq" to "7"),
        "ck_sections__signature_length" to section(VAULT, "billing", "signature" to bytes(64)),
        "ck_sections__write_hash_length" to section(VAULT, "billing", "write_hash" to bytes(31)),
        "ck_sections__change_seq" to section(VAULT, "billing", "change_seq" to "0"),
        "pk_write_pause_requests" to pauseRequest(VAULT, ALICE),
        "fk_write_pause_requests__vault_id__vaults" to pauseRequest(OTHER_VAULT, ALICE),
        "pk_section_removals" to removal(VAULT, 5),
        "fk_section_removals__vault_id__vaults" to removal(OTHER_VAULT, 1),
        "ck_section_removals__change_seq" to removal(VAULT, 0),
        "ck_section_removals__section_name_format" to removal(VAULT, 7, "section_name" to "'Bad'"),
        "pk_nodes" to node(VAULT),
        "fk_nodes__vault_id__vaults" to node(OTHER_VAULT),
        "ck_nodes__created_seq" to node(VAULT, "node_id" to "'$OTHER_NODE'", "created_seq" to "1"),
        "pk_node_shares" to share(VAULT),
        "fk_node_shares__vault_id__vaults" to share(OTHER_VAULT, "home_vault_id" to "'$VAULT'"),
        "ck_node_shares__home_elsewhere" to share(VAULT, "node_id" to "'$OTHER_NODE'", "home_vault_id" to "'$VAULT'"),
        "pk_node_share_names" to shareName(VAULT, "general"),
        "fk_node_share_names__vault_id_node_id__node_shares" to shareName(VAULT, "general", "node_id" to "'$OTHER_NODE'"),
        "ck_node_share_names__section_name_format" to shareName(VAULT, "Bad"),
        "pk_accepted_inviters" to insert("accepted_inviters", mapOf("user_id" to "'$ALICE'", "inviter_user_id" to "'$BOB'", "accepted_at" to NOW), emptyArray()).let { "$it; $it" },
        "ck_vault_log__node_fields" to log(VAULT, 2, *ROLE_SET, "node_id" to "'$NODE'"),
        "ck_vault_log__node_fields" to log(VAULT, 2, "kind" to "'node_created'", "subject_user_id" to "null", "role" to "null", "subject_keys" to "null", "subject_key_version" to "null", "node_id" to "'$NODE'"),
    ).map { (constraint, statement) ->
        DynamicTest.dynamicTest(constraint) {
            val error = assertFailsWith<SQLException> {
                inTransaction { connection -> connection.run(statement) }
            }
            assertTrue(error.message.orEmpty().contains(constraint), "Expected $constraint, got: ${error.message}")
        }
    }

    @Test
    fun `deleting a vault row deletes its keys, members, log, leaves, sections, pauses, removals, nodes and shares`() {
        inTransaction { connection ->
            connection.run("delete from cloak.vaults where id = '$VAULT'")
            for (table in listOf("vault_keys", "vault_members", "vault_log", "checkpoint_leaves", "sections", "write_pause_requests", "section_removals", "nodes", "node_shares", "node_share_names")) {
                val count = connection.createStatement().use { it.executeQuery("select count(*) from cloak.$table").apply { next() }.getInt(1) }
                assertEquals(0, count, table)
            }
        }
    }

    /** Rows and helpers. */
    private companion object {
        /** Seeded user with key version 1, owner of [VAULT]. */
        const val ALICE = "0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e"
        /** Seeded user with key version 1 and no membership. */
        const val BOB = "0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d1f"
        /** User without an identity. */
        const val CAROL = "0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d2a"
        /** Seeded vault. */
        const val VAULT = "0192f5a3-0000-7aaa-8bbb-0123456789ab"
        /** A second seeded vault without a log, for first entries. */
        const val OTHER_VAULT_LOG = "0192f5a3-2222-7aaa-8bbb-0123456789ab"

        /** A vault that does not exist. */
        const val OTHER_VAULT = "0192f5a3-1111-7aaa-8bbb-0123456789ab"
        /** Node of every section row. */
        const val NODE = "0192f5a5-1111-7aaa-8bbb-0123456789ab"
        /** A second node. */
        const val OTHER_NODE = "0192f5a5-2222-7aaa-8bbb-0123456789ab"
        /** Instant of every row. */
        const val NOW = "'2026-11-06T10:00:00Z'"

        /** Fields of a deleted identity: a tombstone (`PROTOCOL.md` §5.7). */
        val DELETED = arrayOf(
            "host_user_id" to "null", "kdf_salt" to "null", "kdf_memory_kib" to "null", "kdf_iterations" to "null",
            "kdf_parallelism" to "null", "private_key_bundle" to "null", "recovery_key_bundle" to "null", "deleted_at" to NOW,
        )

        /** Fields of a valid `member_role_set` entry at seq 2. */
        val ROLE_SET = arrayOf("kind" to "'member_role_set'", "role" to "'admin'")

        /** `n` bytes of `0xaa`. */
        fun bytes(n: Int): String = "decode(repeat('aa', $n), 'hex')"

        fun identity(user: String, vararg changes: Pair<String, String>) = insert(
            "identities",
            mapOf(
                "user_id" to "'$user'", "host_user_id" to "'host-$user'", "key_version" to "1", "kdf_salt" to bytes(16),
                "kdf_memory_kib" to "65536",
                "kdf_iterations" to "3", "kdf_parallelism" to "1", "private_key_bundle" to bytes(170),
                "recovery_key_bundle" to bytes(170), "credentials_version" to "1", "created_at" to NOW, "updated_at" to NOW,
            ),
            changes,
        )

        fun identityKey(user: String, version: Int, signingByte: String, vararg changes: Pair<String, String>) = insert(
            "identity_keys",
            mapOf(
                "user_id" to "'$user'", "key_version" to "$version", "crypto_suite" to "1", "encryption_public_key" to bytes(32),
                "signing_public_key" to "decode(repeat('$signingByte', 32), 'hex')", "recovery_signing_public_key" to bytes(32),
                "keys_digest" to bytes(32), "previous_keys_digest" to if (version == 1) "null" else bytes(32),
                "signature" to bytes(65), "recovery_signature" to if (version == 1) "null" else bytes(65), "created_at" to NOW,
            ),
            changes,
        )

        fun vault(id: String, vararg changes: Pair<String, String>) = insert(
            "vaults",
            mapOf(
                "id" to "'$id'", "key_version" to "1", "log_seq" to "1", "log_head_hash" to bytes(32), "change_seq" to "1",
                "live_section_count" to "0", "stored_section_count" to "0", "created_by_user_id" to "'$ALICE'", "created_at" to NOW,
            ),
            changes,
        )

        fun pauseRequest(vault: String, user: String, vararg changes: Pair<String, String>) = insert(
            "write_pause_requests",
            mapOf("vault_id" to "'$vault'", "user_id" to "'$user'", "paused_at" to NOW),
            changes,
        )

        fun removal(vault: String, changeSeq: Int, vararg changes: Pair<String, String>) = insert(
            "section_removals",
            mapOf("vault_id" to "'$vault'", "change_seq" to "$changeSeq", "node_id" to "'$NODE'", "section_name" to "'general'"),
            changes,
        )

        fun node(vault: String, vararg changes: Pair<String, String>) = insert(
            "nodes",
            mapOf("vault_id" to "'$vault'", "node_id" to "'$NODE'", "owner_user_id" to "'$ALICE'", "node_key" to "'server-1'", "created_seq" to "2"),
            changes,
        )

        fun share(vault: String, vararg changes: Pair<String, String>) = insert(
            "node_shares",
            mapOf(
                "vault_id" to "'$vault'", "node_id" to "'$NODE'", "owner_user_id" to "'$ALICE'", "home_vault_id" to "'$OTHER_VAULT'",
                "node_key" to "'server-1'", "all_since" to "null",
            ),
            changes,
        )

        fun shareName(vault: String, name: String, vararg changes: Pair<String, String>) = insert(
            "node_share_names",
            mapOf("vault_id" to "'$vault'", "node_id" to "'$NODE'", "section_name" to "'$name'", "since" to "3"),
            changes,
        )

        fun vaultKey(vault: String, version: Int, vararg changes: Pair<String, String>) = insert(
            "vault_keys",
            mapOf(
                "vault_id" to "'$vault'", "version" to "$version", "key_commitment" to bytes(32),
                "previous_wrapped_key" to if (version == 1) "null" else bytes(73), "created_at" to NOW,
            ),
            changes,
        )

        fun member(vault: String, user: String, vararg changes: Pair<String, String>) = insert(
            "vault_members",
            mapOf(
                "vault_id" to "'$vault'", "user_id" to "'$user'", "role" to "'owner'", "user_key_version" to "1",
                "keys_digest" to bytes(32), "key_envelope" to bytes(81), "envelope_key_version" to "1", "accepted" to "true", "added_at" to NOW,
            ),
            changes,
        )

        fun log(vault: String, seq: Int, vararg changes: Pair<String, String>) = insert(
            "vault_log",
            mapOf(
                "vault_id" to "'$vault'", "seq" to "$seq", "kind" to "'vault_created'", "subject_user_id" to "'$ALICE'",
                "role" to "'owner'", "key_version" to "1", "subject_keys" to bytes(32), "subject_key_version" to "1",
                "key_commitment" to if (seq == 1) bytes(32) else "null", "checkpoint" to "null", "request_end" to "true",
                "author_user_id" to "'$ALICE'", "author_key_version" to "1", "signature" to bytes(65), "entry_hash" to bytes(32),
                "created_at" to NOW,
            ),
            changes,
        )

        fun checkpointLeaf(vault: String, fromSeq: Int, vararg changes: Pair<String, String>) = insert(
            "checkpoint_leaves",
            mapOf(
                "vault_id" to "'$vault'", "node_id" to "'$NODE'", "section_name" to "'general'", "data_version" to "1",
                "write_hash" to bytes(32), "from_seq" to "$fromSeq", "until_seq" to "null",
            ),
            changes,
        )

        fun section(vault: String, name: String, vararg changes: Pair<String, String>) = insert(
            "sections",
            mapOf(
                "vault_id" to "'$vault'", "node_id" to "'$NODE'", "section_name" to "'$name'", "node_type" to "'compute.vps'",
                "home_vault_id" to "'$vault'", "owner_user_id" to "'$ALICE'", "node_key" to "'server-1'", "vault_key_version" to "1", "data_version" to "1", "deleted" to "false", "log_seq" to "1",
                "log_head_hash" to bytes(32), "previous_write_hash" to "null", "writer_user_id" to "'$ALICE'",
                "writer_key_version" to "1", "ciphertext" to bytes(297), "ciphertext_hash" to bytes(32), "signature" to bytes(65), "write_hash" to bytes(32),
                "change_seq" to "1", "written_at" to NOW,
            ),
            changes,
        )

        /** An insert of [base] with [changes] applied. */
        fun insert(table: String, base: Map<String, String>, changes: Array<out Pair<String, String>>): String {
            val row = base + changes
            return "insert into cloak.$table (${row.keys.joinToString()}) values (${row.values.joinToString()})"
        }

        /** Runs SQL on a connection. */
        fun Connection.run(sql: String) {
            createStatement().use { it.execute(sql) }
        }

        /** Runs [block] in a transaction, rolled back unless [commit]. */
        fun inTransaction(commit: Boolean = false, block: (Connection) -> Unit) {
            TestPostgres.dataSource.connection.use { connection ->
                connection.autoCommit = false
                try {
                    block(connection)
                } finally {
                    if (commit) connection.commit() else connection.rollback()
                }
            }
        }
    }
}
