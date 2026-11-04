package dev.voir.cloak.server.identity.persistence

import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.identity_keys`: every key version of every user with its key
 * statement (`PROTOCOL.md` §5.2). Never updated or deleted.
 */
internal object IdentityKeysTable : Table("cloak.identity_keys") {
    /** Owner of the keys. */
    val userId = uuid("user_id")
        .references(
            IdentitiesTable.userId,
            onDelete = ReferenceOption.RESTRICT,
            onUpdate = ReferenceOption.RESTRICT,
            fkName = "fk_identity_keys__user_id__identities",
        )

    /** Key version, from 1; `ck_identity_keys__chain` enforces it. */
    val keyVersion = integer("key_version")

    /** Algorithm suite of the keys; only `1` exists today. */
    val cryptoSuite = short("crypto_suite").check("ck_identity_keys__crypto_suite") { it eq 1.toShort() }

    /** Raw 32-byte X25519 public key that vault keys are sealed to. */
    val encryptionPublicKey = binary("encryption_public_key")

    /** Raw 32-byte Ed25519 public key that verifies the user's entries and writes. */
    val signingPublicKey = binary("signing_public_key").uniqueIndex("uq_identity_keys__signing_public_key")

    /** Raw 32-byte Ed25519 public key that signs only the next key version. */
    val recoverySigningPublicKey = binary("recovery_signing_public_key")

    /** `keysDigest` of this version: SHA-256 of its fingerprint message. */
    val keysDigest = binary("keys_digest")

    /** `keysDigest` of the previous version; `null` for version 1. */
    val previousKeysDigest = binary("previous_keys_digest").nullable()

    /** Signature of the key statement by this version's signing key. */
    val signature = binary("signature")

    /** Signature of the key statement by the previous version's recovery signing key; `null` for version 1. */
    val recoverySignature = binary("recovery_signature").nullable()

    /** Instant the version was published. */
    val createdAt = timestamp("created_at")

    /** Primary key: one row per user and version. */
    override val primaryKey: PrimaryKey = PrimaryKey(userId, keyVersion, name = "pk_identity_keys")

    init {
        check("ck_identity_keys__encryption_public_key_length") { SqlCondition("octet_length(encryption_public_key) = 32") }
        check("ck_identity_keys__signing_public_key_length") { SqlCondition("octet_length(signing_public_key) = 32") }
        check("ck_identity_keys__recovery_signing_public_key_length") {
            SqlCondition("octet_length(recovery_signing_public_key) = 32")
        }
        check("ck_identity_keys__keys_digest_length") { SqlCondition("octet_length(keys_digest) = 32") }
        check("ck_identity_keys__signature_length") { SqlCondition("octet_length(signature) = 65") }
        check("ck_identity_keys__chain") {
            SqlCondition(
                "(key_version = 1 and previous_keys_digest is null and recovery_signature is null) or " +
                    "(key_version > 1 and previous_keys_digest is not null and recovery_signature is not null " +
                    "and octet_length(previous_keys_digest) = 32 and octet_length(recovery_signature) = 65)",
            )
        }
    }
}
