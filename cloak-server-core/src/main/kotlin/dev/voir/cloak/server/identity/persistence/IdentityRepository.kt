package dev.voir.cloak.server.identity.persistence

import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.domain.Identity
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.KeyStatement
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.persistence.toByteString
import kotlinx.io.bytestring.ByteString
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.core.plus
import org.jetbrains.exposed.v1.core.statements.UpdateBuilder
import org.jetbrains.exposed.v1.core.vendors.ForUpdateOption
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.insertIgnore
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import kotlin.time.Instant

/**
 * Reads and writes `cloak.identities` and `cloak.identity_keys`. Every function runs inside the
 * caller's transaction.
 */
internal object IdentityRepository {
    /**
     * Loads an identity with its current key version.
     *
     * @param userId Owner.
     * @return The identity, or `null` when the user has not registered or is deleted.
     */
    fun find(userId: UserId): Identity? {
        val row = IdentitiesTable.selectAll().where { IdentitiesTable.userId eq userId.value }.singleOrNull() ?: return null
        if (row[IdentitiesTable.deletedAt] != null) return null
        val keys = checkNotNull(findKeys(userId, row[IdentitiesTable.keyVersion])) { "Current key version is missing" }
        return Identity(
            hostUserId = HostUserId.of(checkNotNull(row[IdentitiesTable.hostUserId])),
            keys = keys,
            kdf = KdfParams(
                salt = checkNotNull(row[IdentitiesTable.kdfSalt]).toByteString(),
                memoryKib = checkNotNull(row[IdentitiesTable.kdfMemoryKib]),
                iterations = checkNotNull(row[IdentitiesTable.kdfIterations]),
                parallelism = checkNotNull(row[IdentitiesTable.kdfParallelism]),
            ),
            privateKeyBundle = checkNotNull(row[IdentitiesTable.privateKeyBundle]).toByteString(),
            recoveryKeyBundle = checkNotNull(row[IdentitiesTable.recoveryKeyBundle]).toByteString(),
            credentialsVersion = row[IdentitiesTable.credentialsVersion],
            createdAt = row[IdentitiesTable.createdAt],
            updatedAt = row[IdentitiesTable.updatedAt],
        )
    }

    /**
     * Returns users' current key versions.
     *
     * @param userIds Users.
     * @param lock Whether to hold a shared lock on their rows for the rest of the transaction, so a
     *   key replacement cannot commit between a check and what relies on it.
     * @return Current version by user; users without an identity are absent.
     */
    fun currentKeyVersions(userIds: Collection<UserId>, lock: Boolean = false): Map<UserId, Int> {
        if (userIds.isEmpty()) return emptyMap()
        val query = IdentitiesTable.select(IdentitiesTable.userId, IdentitiesTable.keyVersion)
            .where { IdentitiesTable.userId inList userIds.map(UserId::value) }
        if (lock) query.forUpdate(ForUpdateOption.PostgreSQL.ForShare())
        return query.associate { UserId(it[IdentitiesTable.userId]) to it[IdentitiesTable.keyVersion] }
    }

    /**
     * Loads one key version.
     *
     * @param userId Owner.
     * @param keyVersion Key version.
     * @return The keys, or `null` when the version does not exist.
     */
    fun findKeys(userId: UserId, keyVersion: Int): PublicKeys? =
        IdentityKeysTable.selectAll()
            .where { (IdentityKeysTable.userId eq userId.value) and (IdentityKeysTable.keyVersion eq keyVersion) }
            .singleOrNull()
            ?.toPublicKeys()

    /**
     * Loads every key version of several users, oldest first, in one query.
     *
     * @param userIds Users.
     * @return Statements by user; users without an identity are absent.
     */
    fun statements(userIds: Collection<UserId>): Map<UserId, List<KeyStatement>> {
        if (userIds.isEmpty()) return emptyMap()
        return IdentityKeysTable.selectAll()
            .where { IdentityKeysTable.userId inList userIds.map(UserId::value) }
            .orderBy(IdentityKeysTable.userId to SortOrder.ASC, IdentityKeysTable.keyVersion to SortOrder.ASC)
            .map { it.toStatement() }
            .groupBy { it.keys.userId }
    }

    /**
     * Returns users' host user ids.
     *
     * @param userIds Users.
     * @return Host user id by user, `null` for a deleted one; users without an identity are absent.
     */
    fun hostUserIds(userIds: Collection<UserId>): Map<UserId, HostUserId?> {
        if (userIds.isEmpty()) return emptyMap()
        return IdentitiesTable.select(IdentitiesTable.userId, IdentitiesTable.hostUserId)
            .where { IdentitiesTable.userId inList userIds.map(UserId::value) }
            .associate { UserId(it[IdentitiesTable.userId]) to it[IdentitiesTable.hostUserId]?.let(HostUserId::of) }
    }

    /**
     * Tells whether a user's identity is deleted.
     *
     * @param userId User.
     * @param lock Whether to hold a key-share lock on the row for the rest of the transaction, so an
     *   erasure, which locks the row for update, cannot commit until the transaction ends.
     * @return Whether the identity is a tombstone; `false` when the user never registered.
     */
    fun isDeleted(userId: UserId, lock: Boolean): Boolean {
        val query = IdentitiesTable.select(IdentitiesTable.deletedAt).where { IdentitiesTable.userId eq userId.value }
        if (lock) query.forUpdate(ForUpdateOption.PostgreSQL.ForKeyShare)
        return query.singleOrNull()?.get(IdentitiesTable.deletedAt) != null
    }

    /**
     * Returns which of some users are deleted.
     *
     * @param userIds Users.
     * @param lock Whether to hold a key-share lock on their rows for the rest of the transaction.
     * @return The deleted ones.
     */
    fun deleted(userIds: Collection<UserId>, lock: Boolean = false): Set<UserId> {
        if (userIds.isEmpty()) return emptySet()
        val query = IdentitiesTable.select(IdentitiesTable.userId, IdentitiesTable.deletedAt)
            .where { IdentitiesTable.userId inList userIds.map(UserId::value) }
        if (lock) query.forUpdate(ForUpdateOption.PostgreSQL.ForKeyShare)
        return query.filter { it[IdentitiesTable.deletedAt] != null }.map { UserId(it[IdentitiesTable.userId]) }.toSet()
    }

    /**
     * Locks an identity for update, for its deletion.
     *
     * @param userId User.
     * @return Whether the identity exists and is not deleted.
     */
    fun lockLive(userId: UserId): Boolean =
        IdentitiesTable.select(IdentitiesTable.deletedAt)
            .where { IdentitiesTable.userId eq userId.value }
            .forUpdate(ForUpdateOption.PostgreSQL.ForUpdate())
            .singleOrNull()
            ?.let { it[IdentitiesTable.deletedAt] == null } ?: false

    /**
     * Turns an identity into a tombstone (`PROTOCOL.md` §5.7): erases its host user id, KDF
     * parameters and both bundles. Its key versions stay. Lock it with [lockLive] first.
     *
     * @param userId User.
     * @param now Deletion instant.
     */
    fun tombstone(userId: UserId, now: Instant) {
        IdentitiesTable.update(where = { (IdentitiesTable.userId eq userId.value) and IdentitiesTable.deletedAt.isNull() }) {
            it[hostUserId] = null
            it[kdfSalt] = null
            it[kdfMemoryKib] = null
            it[kdfIterations] = null
            it[kdfParallelism] = null
            it[privateKeyBundle] = null
            it[recoveryKeyBundle] = null
            it[updatedAt] = now
            it[deletedAt] = now
        }
    }

    /**
     * Tells whether any user's key version already uses a signing key.
     *
     * @param signingPublicKey Raw Ed25519 public key.
     * @return Whether the key is taken.
     */
    fun isSigningKeyTaken(signingPublicKey: ByteString): Boolean =
        !IdentityKeysTable.select(IdentityKeysTable.userId)
            .where { IdentityKeysTable.signingPublicKey eq signingPublicKey.toByteArray() }
            .empty()

    /**
     * Stores a new identity at key version 1 unless its user id has a row, live or deleted; insert
     * its statement right after. The primary key decides, so two registrations racing cannot both
     * succeed, and a tombstone's user id never registers again.
     *
     * @param hostUserId Owner, by the host's id; the user id derives from it.
     * @param kdf Argon2id parameters.
     * @param privateKeyBundle Bundle under the master key.
     * @param recoveryKeyBundle Bundle under the recovery key.
     * @param now Registration instant.
     * @return Whether the identity was stored; `false` when the user id already has a row.
     */
    fun insertIdentity(hostUserId: HostUserId, kdf: KdfParams, privateKeyBundle: ByteString, recoveryKeyBundle: ByteString, now: Instant): Boolean =
        IdentitiesTable.insertIgnore {
            it[IdentitiesTable.userId] = hostUserId.userId.value
            it[IdentitiesTable.hostUserId] = hostUserId.value
            it[keyVersion] = 1
            it[kdfSalt] = kdf.salt.toByteArray()
            it[kdfMemoryKib] = kdf.memoryKib
            it[kdfIterations] = kdf.iterations
            it[kdfParallelism] = kdf.parallelism
            it[IdentitiesTable.privateKeyBundle] = privateKeyBundle.toByteArray()
            it[IdentitiesTable.recoveryKeyBundle] = recoveryKeyBundle.toByteArray()
            it[credentialsVersion] = 1
            it[createdAt] = now
            it[updatedAt] = now
        }.insertedCount == 1

    /**
     * Stores a key version with its statement.
     *
     * @param statement The verified statement.
     * @param keysDigest `keysDigest` of the version.
     */
    fun insertStatement(statement: KeyStatement, keysDigest: ByteString) {
        val keys = statement.keys
        IdentityKeysTable.insert {
            it[userId] = keys.userId.value
            it[keyVersion] = keys.keyVersion
            it[cryptoSuite] = keys.cryptoSuite.toShort()
            it[encryptionPublicKey] = keys.encryptionPublicKey.toByteArray()
            it[signingPublicKey] = keys.signingPublicKey.toByteArray()
            it[recoverySigningPublicKey] = keys.recoverySigningPublicKey.toByteArray()
            it[IdentityKeysTable.keysDigest] = keysDigest.toByteArray()
            it[previousKeysDigest] = statement.previousKeysDigest?.toByteArray()
            it[signature] = statement.signature.toByteArray()
            it[recoverySignature] = statement.recoverySignature?.toByteArray()
            it[createdAt] = statement.createdAt
        }
    }

    /**
     * Replaces the private key bundle and KDF parameters when the credentials version is still
     * [expectedVersion].
     *
     * @param userId Owner.
     * @param expectedVersion Version the client read.
     * @param kdf New KDF parameters.
     * @param privateKeyBundle New bundle.
     * @param now Update instant.
     * @return Whether the row was updated; `false` means the version moved on.
     */
    fun updateCredentials(userId: UserId, expectedVersion: Int, kdf: KdfParams, privateKeyBundle: ByteString, now: Instant): Boolean =
        IdentitiesTable.update(
            where = { (IdentitiesTable.userId eq userId.value) and (IdentitiesTable.credentialsVersion eq expectedVersion) },
        ) {
            it.setKdf(kdf)
            it[IdentitiesTable.privateKeyBundle] = privateKeyBundle.toByteArray()
            it[credentialsVersion] = expectedVersion + 1
            it[updatedAt] = now
        } == 1

    /**
     * Moves an identity to its next key version when it is still at [expectedKeyVersion], with the
     * new bundles; insert the new statement right after.
     *
     * @param userId Owner.
     * @param expectedKeyVersion Version the new one follows.
     * @param kdf New KDF parameters.
     * @param privateKeyBundle New bundle under the master key.
     * @param recoveryKeyBundle New bundle under the recovery key.
     * @param now Update instant.
     * @return Whether the row was updated; `false` means the keys moved on.
     */
    fun advanceKeys(
        userId: UserId,
        expectedKeyVersion: Int,
        kdf: KdfParams,
        privateKeyBundle: ByteString,
        recoveryKeyBundle: ByteString,
        now: Instant,
    ): Boolean =
        IdentitiesTable.update(
            where = { (IdentitiesTable.userId eq userId.value) and (IdentitiesTable.keyVersion eq expectedKeyVersion) },
        ) {
            it[keyVersion] = expectedKeyVersion + 1
            it.setKdf(kdf)
            it[IdentitiesTable.privateKeyBundle] = privateKeyBundle.toByteArray()
            it[IdentitiesTable.recoveryKeyBundle] = recoveryKeyBundle.toByteArray()
            // New keys start the credentials over (`PROTOCOL.md` §5.4): every credentials statement
            // names its key version, so none made for the old keys verifies with the new ones.
            it[credentialsVersion] = 1
            it[updatedAt] = now
        } == 1

    /** Sets the KDF columns. */
    private fun UpdateBuilder<*>.setKdf(kdf: KdfParams) {
        this[IdentitiesTable.kdfSalt] = kdf.salt.toByteArray()
        this[IdentitiesTable.kdfMemoryKib] = kdf.memoryKib
        this[IdentitiesTable.kdfIterations] = kdf.iterations
        this[IdentitiesTable.kdfParallelism] = kdf.parallelism
    }

    /** Maps the public-key columns. */
    private fun ResultRow.toPublicKeys(): PublicKeys =
        PublicKeys(
            userId = UserId(this[IdentityKeysTable.userId]),
            keyVersion = this[IdentityKeysTable.keyVersion],
            cryptoSuite = this[IdentityKeysTable.cryptoSuite].toInt(),
            encryptionPublicKey = this[IdentityKeysTable.encryptionPublicKey].toByteString(),
            signingPublicKey = this[IdentityKeysTable.signingPublicKey].toByteString(),
            recoverySigningPublicKey = this[IdentityKeysTable.recoverySigningPublicKey].toByteString(),
        )

    /** Maps a full key row. */
    private fun ResultRow.toStatement(): KeyStatement =
        KeyStatement(
            keys = toPublicKeys(),
            previousKeysDigest = this[IdentityKeysTable.previousKeysDigest]?.toByteString(),
            signature = this[IdentityKeysTable.signature].toByteString(),
            recoverySignature = this[IdentityKeysTable.recoverySignature]?.toByteString(),
            createdAt = this[IdentityKeysTable.createdAt],
        )
}
