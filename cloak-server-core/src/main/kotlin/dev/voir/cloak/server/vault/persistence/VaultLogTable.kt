package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.persistence.IdentityKeysTable
import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.vault_log`: the signed, hash-chained history of a vault
 * (`PROTOCOL.md` §7). Append-only. The subject is a plain id: removed members' entries remain.
 */
internal object VaultLogTable : Table("cloak.vault_log") {
    /** Vault; deleting it deletes its log. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_vault_log__vault_id__vaults",
        )

    /** Position in the log, from 1. */
    val seq = long("seq")

    /** Kind code. */
    val kind = varchar("kind", 32)

    /** User subject, if the kind has one. */
    val subjectUserId = uuid("subject_user_id").nullable()

    /** Role set, if the kind has one. */
    val role = varchar("role", 16).nullable()

    /** Vault key version once the entry applies. */
    val keyVersion = integer("key_version").check("ck_vault_log__key_version") { it greaterEq 1 }

    /** `keysDigest` of the subject's keys. */
    val subjectKeys = binary("subject_keys").nullable()

    /** The subject's identity key version. */
    val subjectKeyVersion = integer("subject_key_version").nullable()

    /** Commitment of the key version the entry creates. */
    val keyCommitment = binary("key_commitment").nullable()

    /** Merkle root over the vault's latest writes. */
    val checkpoint = binary("checkpoint").nullable()

    /** Number of leaves of the checkpoint; present exactly when [checkpoint] is. */
    val checkpointSize = integer("checkpoint_size").nullable()

    /** Whether the entry ends its request, a head a write may cite. */
    val requestEnd = bool("request_end")

    /** Author, who signed the entry. */
    val authorUserId = uuid("author_user_id")

    /** The author's identity key version that signed. */
    val authorKeyVersion = integer("author_key_version")

    /** Node a node entry names (`PROTOCOL.md` §7.7). */
    val nodeId = uuid("node_id").nullable()

    /** Home vault of the node `node_shared` shares. */
    val homeVaultId = uuid("home_vault_id").nullable()

    /** Key of the node `node_created` creates or `node_shared` shares. */
    val nodeKey = varchar("node_key", 255).nullable()

    /** Names a node entry covers: `*`, or names ascending and comma-joined. */
    val sections = varchar("sections", 6500).nullable()

    /** Author's signature over the entry's canonical message. */
    val signature = binary("signature")

    /** SHA-256 of the entry's canonical message; 32 bytes. */
    val entryHash = binary("entry_hash")

    /** Instant the entry was appended. */
    val createdAt = timestamp("created_at")

    /** Primary key: one entry per position of a vault's log. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, seq, name = "pk_vault_log")

    init {
        foreignKey(
            authorUserId to IdentityKeysTable.userId,
            authorKeyVersion to IdentityKeysTable.keyVersion,
            onDelete = ReferenceOption.RESTRICT,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_vault_log__author_user_id_author_key_version__identity_keys",
        )
        index("ix_vault_log__author_user_id_author_key_version", false, authorUserId, authorKeyVersion)
        check("ck_vault_log__role") { SqlCondition("role is null or role in ('owner', 'admin', 'editor', 'viewer')") }
        check("ck_vault_log__signature_length") { SqlCondition("octet_length(signature) = 65") }
        check("ck_vault_log__entry_hash_length") { SqlCondition("octet_length(entry_hash) = 32") }
        check("ck_vault_log__subject_keys_complete") {
            SqlCondition(
                "(subject_keys is null and subject_key_version is null) or " +
                    "(subject_keys is not null and subject_key_version is not null and " +
                    "octet_length(subject_keys) = 32 and subject_key_version >= 1)",
            )
        }
        check("ck_vault_log__key_commitment_length") {
            SqlCondition("key_commitment is null or octet_length(key_commitment) = 32")
        }
        check("ck_vault_log__checkpoint_length") { SqlCondition("checkpoint is null or octet_length(checkpoint) = 32") }
        check("ck_vault_log__checkpoint_size") {
            SqlCondition(
                "(checkpoint is null and checkpoint_size is null) or " +
                    "(checkpoint is not null and checkpoint_size is not null and checkpoint_size >= 0)",
            )
        }
        check("ck_vault_log__kind_shape") { SqlCondition(KIND_SHAPE) }
        check("ck_vault_log__node_fields") { SqlCondition(NODE_FIELDS) }
    }

    /** Which node fields each kind sets; the same condition as the migration's check. */
    private val NODE_FIELDS: String
        get() = listOf(
            "kind = 'node_created' and node_id is not null and home_vault_id is null and node_key is not null and sections is null",
            "kind = 'node_shared' and node_id is not null and home_vault_id is not null and node_key is not null and sections is not null",
            "kind = 'node_unshared' and node_id is not null and home_vault_id is null and node_key is null and sections is not null",
            "kind not in ('node_created', 'node_shared', 'node_unshared') and node_id is null and home_vault_id is null and node_key is null and sections is null",
        ).joinToString(" or ") { "($it)" }

    /** Which fields each kind sets; the same condition as the migration's check. */
    private val KIND_SHAPE: String
        get() = listOf(
            "kind = 'vault_created' and seq = 1 and subject_user_id is not null and coalesce(role, '') = 'owner' and subject_keys is not null and key_commitment is not null and checkpoint is null",
            "kind = 'member_added' and seq > 1 and subject_user_id is not null and role is not null and subject_keys is not null and key_commitment is null and checkpoint is null",
            "kind = 'member_role_set' and seq > 1 and subject_user_id is not null and role is not null and subject_keys is not null and key_commitment is null",
            "kind = 'member_removed' and seq > 1 and subject_user_id is not null and role is null and subject_keys is not null and key_commitment is null",
            "kind = 'member_keys_replaced' and seq > 1 and subject_user_id is not null and role is null and subject_keys is not null and key_commitment is null",
            "kind = 'key_rotated' and seq > 1 and subject_user_id is null and role is null and subject_keys is null and key_commitment is not null and checkpoint is not null",
            "kind in ('node_created', 'node_shared', 'node_unshared', 'vault_deleted') and seq > 1 and subject_user_id is null and role is null and subject_keys is null and key_commitment is null and checkpoint is null",
        ).joinToString(" or ") { "($it)" }
}
