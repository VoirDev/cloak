package dev.voir.cloak.server.identity.persistence

import dev.voir.cloak.server.persistence.SqlCondition
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.datetime.timestamp

/**
 * Relational schema of `cloak.identities`: a registered user's current key version and the
 * credentials that unlock it. Every key version is in [IdentityKeysTable].
 *
 * A deleted identity is a tombstone (`PROTOCOL.md` §5.7): [deletedAt] is set and the host user id,
 * the KDF parameters and both bundles are `null`; the row stays so its user id never registers again.
 *
 * Checks the DSL cannot express are declared with [SqlCondition], identical to the migration.
 */
internal object IdentitiesTable : Table("cloak.identities") {
    /** Host user that owns this identity; also the primary key. */
    val userId = uuid("user_id")

    /** The host's id of the user, from which [userId] derives (`PROTOCOL.md` §5.0); `null` once deleted. */
    val hostUserId = varchar("host_user_id", 255).nullable().uniqueIndex("uq_identities__host_user_id")

    /** Current identity key version; a row of [IdentityKeysTable] always exists for it. */
    val keyVersion = integer("key_version").check("ck_identities__key_version") { it greaterEq 1 }

    /** 16-byte Argon2id salt for deriving the master key; `null` once deleted. */
    val kdfSalt = binary("kdf_salt").nullable()

    /** Argon2id memory cost in KiB, within the protocol's bounds; `null` once deleted. */
    val kdfMemoryKib = integer("kdf_memory_kib").nullable()

    /** Argon2id iteration count, within the protocol's bounds; `null` once deleted. */
    val kdfIterations = integer("kdf_iterations").nullable()

    /** Argon2id parallelism; always 1 in crypto suite 1; `null` once deleted. */
    val kdfParallelism = integer("kdf_parallelism").nullable().check("ck_identities__kdf_parallelism") { it eq 1 }

    /** Private keys of [keyVersion] encrypted under the master key; opaque versioned blob; `null` once deleted. */
    val privateKeyBundle = binary("private_key_bundle").nullable()

    /** Private keys of [keyVersion] encrypted under the recovery key; opaque versioned blob; `null` once deleted. */
    val recoveryKeyBundle = binary("recovery_key_bundle").nullable()

    /** Optimistic-lock version of the credentials; bumped by every change of the bundles. */
    val credentialsVersion = integer("credentials_version")
        .check("ck_identities__credentials_version") { it greaterEq 1 }

    /** Instant the identity was registered. */
    val createdAt = timestamp("created_at")

    /** Instant the credentials or keys last changed, or the identity was deleted. */
    val updatedAt = timestamp("updated_at")

    /** Instant the identity was deleted; `null` while it is in use. */
    val deletedAt = timestamp("deleted_at").nullable()

    /** Primary key: one identity per host user. */
    override val primaryKey: PrimaryKey = PrimaryKey(userId, name = "pk_identities")

    init {
        check("ck_identities__host_user_id_length") { SqlCondition("octet_length(host_user_id) between 1 and 255") }
        check("ck_identities__kdf_salt_length") { SqlCondition("octet_length(kdf_salt) = 16") }
        check("ck_identities__kdf_memory_kib") { SqlCondition("kdf_memory_kib between 65536 and 1048576") }
        check("ck_identities__kdf_iterations") { SqlCondition("kdf_iterations between 2 and 10") }
        check("ck_identities__updated_after_created") { SqlCondition("updated_at >= created_at") }
        check("ck_identities__deleted") {
            SqlCondition(
                "(deleted_at is null and host_user_id is not null and kdf_salt is not null and kdf_memory_kib is not null " +
                    "and kdf_iterations is not null and kdf_parallelism is not null and private_key_bundle is not null " +
                    "and recovery_key_bundle is not null) or " +
                    "(deleted_at is not null and host_user_id is null and kdf_salt is null and kdf_memory_kib is null " +
                    "and kdf_iterations is null and kdf_parallelism is null and private_key_bundle is null " +
                    "and recovery_key_bundle is null)",
            )
        }
    }
}
