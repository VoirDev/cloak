package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.identity.persistence.IdentityKeysTable
import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.datetime.timestamp
import org.jetbrains.exposed.v1.core.Table

/**
 * Relational schema of `cloak.vault_members`: members with their role, committed key version and
 * the current vault key sealed to them; the envelope is absent while it awaits delivery.
 */
internal object VaultMembersTable : Table("cloak.vault_members") {
    /** Vault; deleting it deletes its members. */
    val vaultId = uuid("vault_id")
        .references(
            VaultsTable.id,
            onDelete = ReferenceOption.CASCADE,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_vault_members__vault_id__vaults",
        )

    /** Member. */
    val userId = uuid("user_id").index("ix_vault_members__user_id")

    /** Whether the member accepted the vault (`PROTOCOL.md` §12.4); unsigned, the server's help. */
    val accepted = bool("accepted")

    /** Who added the member, per the log; `null` for the vault's creator. */
    val addedByUserId = uuid("added_by_user_id").nullable()

    /** Role: owner, admin, editor or viewer. */
    val role = varchar("role", 16)

    /** Committed identity key version; only it carries the member's rights. */
    val userKeyVersion = integer("user_key_version")

    /** `keysDigest` of the committed version, as the log committed it. */
    val keysDigest = binary("keys_digest")

    /** The current vault key sealed to the committed keys; `null` while awaiting delivery. */
    val keyEnvelope = binary("key_envelope").nullable()

    /** Vault key version [keyEnvelope] holds; `null` with it. */
    val envelopeKeyVersion = integer("envelope_key_version").nullable()

    /** Instant the member was added. */
    val addedAt = timestamp("added_at")

    /** Primary key: one membership per vault and user. */
    override val primaryKey: PrimaryKey = PrimaryKey(vaultId, userId, name = "pk_vault_members")

    init {
        foreignKey(
            userId to IdentityKeysTable.userId,
            userKeyVersion to IdentityKeysTable.keyVersion,
            onDelete = ReferenceOption.RESTRICT,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_vault_members__user_id_user_key_version__identity_keys",
        )
        foreignKey(
            vaultId to VaultKeysTable.vaultId,
            envelopeKeyVersion to VaultKeysTable.version,
            onDelete = ReferenceOption.NO_ACTION,
            onUpdate = ReferenceOption.RESTRICT,
            name = "fk_vault_members__vault_id_envelope_key_version__vault_keys",
        )
        index("ix_vault_members__user_id_accepted", false, userId, accepted)
        check("ck_vault_members__role") { SqlCondition("role in ('owner', 'admin', 'editor', 'viewer')") }
        check("ck_vault_members__keys_digest_length") { SqlCondition("octet_length(keys_digest) = 32") }
        check("ck_vault_members__envelope_complete") {
            SqlCondition(
                "(key_envelope is null and envelope_key_version is null) or " +
                    "(key_envelope is not null and envelope_key_version is not null and octet_length(key_envelope) = 81)",
            )
        }
    }
}
