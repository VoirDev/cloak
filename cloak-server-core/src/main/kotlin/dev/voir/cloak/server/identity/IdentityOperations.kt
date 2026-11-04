package dev.voir.cloak.server.identity

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.DeleteIdentityCommand
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.domain.Identity
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.KeyStatement
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.RegisterIdentityCommand
import dev.voir.cloak.server.identity.domain.ReplaceKeysCommand
import dev.voir.cloak.server.identity.domain.UpdateCredentialsCommand
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.identity.domain.UserKeys
import dev.voir.cloak.server.identity.domain.UserKeysBatch
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.StrictEd25519
import kotlinx.io.bytestring.ByteString

/**
 * The caller's own identity and other users' key versions (`/identity`, `/users`).
 *
 * @property context Database and clock.
 */
public class IdentityOperations internal constructor(
    private val context: CloakContext,
) {
    /**
     * Returns the caller's identity, so a client can unlock locally.
     *
     * @param caller Authenticated user.
     * @return The identity at its current key version.
     * @throws CloakException `identity_required` when the caller has not registered.
     */
    public fun get(caller: UserId): Identity =
        context.operation("getIdentity") {
            asCaller(caller) { IdentityRepository.find(caller) ?: throw CloakException.identityRequired() }
        }

    /**
     * Registers the caller's identity at key version 1 (`PROTOCOL.md` §12.1). The user id is the
     * one derived from [caller] (§5.0), and the host id is kept beside it.
     *
     * @param caller Authenticated user, by the host's id.
     * @param command Public keys, the self-signed statement, KDF parameters and both bundles.
     * @return The stored identity.
     * @throws CloakException `already_exists` when the caller or the signing key is registered,
     *   `identity_deleted` when the caller's identity was deleted, which never registers again,
     *   `unsupported_format` for an unknown suite, `bad_signature` when the statement does not
     *   verify, `validation_failed` for malformed values.
     */
    public fun register(caller: HostUserId, command: RegisterIdentityCommand): Identity = context.operation("registerIdentity") {
        val userId = caller.userId
        if (command.cryptoSuite != CRYPTO_SUITE) {
            throw CloakException(CloakErrorCode.UNSUPPORTED_FORMAT, "Crypto suite ${command.cryptoSuite} is not supported.")
        }
        val keys = PublicKeys(
            userId = userId,
            keyVersion = 1,
            cryptoSuite = command.cryptoSuite,
            encryptionPublicKey = command.encryptionPublicKey,
            signingPublicKey = command.signingPublicKey,
            recoverySigningPublicKey = command.recoverySigningPublicKey,
        )
        checkKeys(keys)
        BlobRules.signature(command.signature, "/signature")
        checkKdf(command.kdf)
        BlobRules.bundle(command.privateKeyBundle, "/privateKeyBundle")
        BlobRules.bundle(command.recoveryKeyBundle, "/recoveryKeyBundle")
        requireSignature(keys.signingPublicKey, Messages.keyStatement(keys, null), command.signature, "/signature")
        withoutCaller {
            if (IdentityRepository.currentKeyVersions(listOf(userId)).isNotEmpty()) {
                if (IdentityRepository.isDeleted(userId, lock = false)) throw CloakException.identityDeleted()
                throw CloakException(CloakErrorCode.ALREADY_EXISTS, "You already have an identity.")
            }
            requireFreshSigningKey(keys.signingPublicKey)
            val now = context.clock.now()
            // The primary key decides between racing registrations, and keeps a deleted user id from
            // registering again: the memberships a host erasure left would pass to its new holder.
            if (!IdentityRepository.insertIdentity(caller, command.kdf, command.privateKeyBundle, command.recoveryKeyBundle, now)) {
                if (IdentityRepository.isDeleted(userId, lock = false)) throw CloakException.identityDeleted()
                throw CloakException(CloakErrorCode.ALREADY_EXISTS, "You already have an identity.")
            }
            IdentityRepository.insertStatement(KeyStatement(keys, null, command.signature, null, now), Messages.keysDigest(keys))
            checkNotNull(IdentityRepository.find(userId))
        }
    }

    /**
     * Replaces the private key bundle and KDF parameters after a password change or a recovery
     * (`PROTOCOL.md` §5.4, §5.5). Keys and the recovery key do not change. The change is signed with
     * the caller's current signing key, so someone holding only the host's session cannot replace
     * the bundle and lock the user out.
     *
     * @param caller Authenticated user.
     * @param command Expected credentials version, KDF parameters, bundle and signature.
     * @return The updated identity, at the next credentials version.
     * @throws CloakException `credentials_version_conflict` when another device changed them first,
     *   `bad_signature` when the credentials statement does not verify with the current keys.
     */
    public fun updateCredentials(caller: UserId, command: UpdateCredentialsCommand): Identity = context.operation("updateCredentials") {
        checkKdf(command.kdf)
        BlobRules.bundle(command.privateKeyBundle, "/privateKeyBundle")
        BlobRules.signature(command.signature, "/signature")
        asCaller(caller) {
            val current = IdentityRepository.find(caller) ?: throw CloakException.identityRequired()
            if (command.expectedCredentialsVersion == current.credentialsVersion) {
                val message = Messages.credentials(
                    caller,
                    current.keys.keyVersion,
                    command.expectedCredentialsVersion + 1,
                    command.privateKeyBundle,
                    command.kdf,
                )
                requireSignature(current.keys.signingPublicKey, message, command.signature, "/signature")
            }
            val updated = command.expectedCredentialsVersion == current.credentialsVersion &&
                IdentityRepository.updateCredentials(
                    caller,
                    command.expectedCredentialsVersion,
                    command.kdf,
                    command.privateKeyBundle,
                    context.clock.now(),
                )
            if (!updated) {
                throw CloakException(
                    CloakErrorCode.CREDENTIALS_VERSION_CONFLICT,
                    "Your credentials changed on another device.",
                    currentVersion = current.credentialsVersion.toLong(),
                )
            }
            checkNotNull(IdentityRepository.find(caller))
        }
    }

    /**
     * Replaces the caller's identity keys with the next version (`PROTOCOL.md` §5.6). The statement
     * must be signed by the new signing key and by the current version's recovery signing key, so
     * neither a thief of the device keys nor the server can make one.
     *
     * @param caller Authenticated user.
     * @param command The new keys, both signatures and the new bundles.
     * @return The identity at the new key version.
     * @throws CloakException `identity_version_conflict` unless [ReplaceKeysCommand.expectedKeyVersion]
     *   is the current version, `bad_signature` when either signature does not verify,
     *   `already_exists` when the signing key is taken.
     */
    public fun replaceKeys(caller: UserId, command: ReplaceKeysCommand): Identity = context.operation("replaceKeys") {
        BlobRules.signature(command.signature, "/signature")
        BlobRules.signature(command.recoverySignature, "/recoverySignature")
        checkKdf(command.kdf)
        BlobRules.bundle(command.privateKeyBundle, "/privateKeyBundle")
        BlobRules.bundle(command.recoveryKeyBundle, "/recoveryKeyBundle")
        asCaller(caller) {
            val current = IdentityRepository.find(caller) ?: throw CloakException.identityRequired()
            if (command.expectedKeyVersion != current.keys.keyVersion) throw versionConflict(current.keys.keyVersion)
            val keys = PublicKeys(
                userId = caller,
                keyVersion = current.keys.keyVersion + 1,
                cryptoSuite = CRYPTO_SUITE,
                encryptionPublicKey = command.encryptionPublicKey,
                signingPublicKey = command.signingPublicKey,
                recoverySigningPublicKey = command.recoverySigningPublicKey,
            )
            checkKeys(keys)
            val previousDigest = Messages.keysDigest(current.keys)
            val message = Messages.keyStatement(keys, previousDigest)
            requireSignature(keys.signingPublicKey, message, command.signature, "/signature")
            requireSignature(current.keys.recoverySigningPublicKey, message, command.recoverySignature, "/recoverySignature")
            requireFreshSigningKey(keys.signingPublicKey)
            val now = context.clock.now()
            val advanced = IdentityRepository.advanceKeys(
                caller,
                command.expectedKeyVersion,
                command.kdf,
                command.privateKeyBundle,
                command.recoveryKeyBundle,
                now,
            )
            if (!advanced) throw versionConflict(current.keys.keyVersion)
            IdentityRepository.insertStatement(
                KeyStatement(keys, previousDigest, command.signature, command.recoverySignature, now),
                Messages.keysDigest(keys),
            )
            checkNotNull(IdentityRepository.find(caller))
        }
    }

    /**
     * Deletes the caller's identity (`PROTOCOL.md` §5.7): erases its host user id, KDF parameters and
     * both bundles and keeps its key versions, which signed entries name. Afterwards every request of
     * the caller answers `identity_deleted`, and the user id never registers again.
     *
     * The deletion is signed with the caller's current signing key, so the host's session alone
     * cannot delete an account, and it expires at `notAfter`, at most 10 minutes ahead, so a
     * captured one cannot be sent again later.
     *
     * @param caller Authenticated user.
     * @param command The current credentials version, the expiry and the signature.
     * @throws CloakException `identity_required` when the caller has no identity, `validation_failed`
     *   for a statement past `notAfter` or further ahead than allowed, `credentials_version_conflict`
     *   when the credentials changed since, `bad_signature`, and `identity_in_vaults` while the caller
     *   is an accepted member of a vault that is not deleted: they delete or leave those first. Vaults
     *   they never accepted keep their membership in the log, with no envelope, as after [erase].
     */
    public fun delete(caller: UserId, command: DeleteIdentityCommand) {
        BlobRules.signature(command.signature, "/signature")
        context.operation("deleteIdentity") {
            val now = context.clock.now().epochSeconds
            Validation.require(command.notAfter >= now, "/notAfter", "expired", "The statement has expired; sign a new one.")
            Validation.require(
                command.notAfter <= now + MAX_DELETION_VALIDITY_SECONDS,
                "/notAfter",
                "maximum",
                "At most $MAX_DELETION_VALIDITY_SECONDS seconds ahead.",
            )
            asCaller(caller) {
                // Vaults first, then the identity, the order erasure locks them in, so clearing the
                // envelopes below never waits on a request that holds one of these vaults.
                VaultRepository.lock(MemberRepository.vaultsOf(caller))
                if (!IdentityRepository.lockLive(caller)) throw CloakException.identityRequired()
                val current = IdentityRepository.find(caller) ?: throw CloakException.identityRequired()
                if (command.credentialsVersion != current.credentialsVersion) {
                    throw CloakException(
                        CloakErrorCode.CREDENTIALS_VERSION_CONFLICT,
                        "Your credentials changed on another device.",
                        currentVersion = current.credentialsVersion.toLong(),
                    )
                }
                val message = Messages.identityDeletion(caller, current.keys.keyVersion, command.credentialsVersion, command.notAfter)
                requireSignature(current.keys.signingPublicKey, message, command.signature, "/signature")
                // Locked for update: nobody can add the caller to a vault until this commits. A
                // deleted vault's members are no longer members anywhere (§12.3), and a vault the
                // caller never accepted does not hold their account (§12.4).
                if (MemberRepository.acceptedLiveVaultsOf(caller).isNotEmpty()) {
                    throw CloakException(
                        CloakErrorCode.IDENTITY_IN_VAULTS,
                        "Delete or leave every vault you accepted before deleting your identity.",
                    )
                }
                // The memberships never accepted stay in the logs, as after an erasure: members see
                // them marked deleted and an admin removes them with a rotation. Nothing stays
                // sealed to the deleted keys.
                MemberRepository.clearEnvelopes(caller)
                IdentityRepository.tombstone(caller, context.clock.now())
            }
        }
    }

    /**
     * Deletes a user's identity on the host's behalf (`PROTOCOL.md` §5.7), for a user who cannot or
     * will not do it themselves, such as on an erasure request or a closed account. Not part of the
     * API: call it from the host's own code.
     *
     * Erases the identity as [delete] does, removes the vault-key envelopes sealed to it, and deletes
     * the vaults where the user was the only member. Nobody can sign for the user, so their other
     * memberships stay in the logs: members see them marked deleted, and an admin removes them with
     * a rotation. Deletion does not revoke keys: what the user signed stays valid, and whoever holds
     * their keys keeps knowing the vault keys they knew until admins remove them and rotate.
     *
     * Idempotent: erasing a deleted or never registered user changes nothing.
     *
     * @param hostUserId The host's id of the user.
     * @return Whether an identity was erased by this call.
     */
    public fun erase(hostUserId: HostUserId): Boolean = context.operation("eraseIdentity") {
        val userId = hostUserId.userId
        withoutCaller(CloakContext.Budget.CHECKPOINT) {
            // Vaults first, then the identity, the order every request locks them in. A vault joined
            // after the first read has another member, so it is never one to delete.
            val sole = VaultRepository.lock(MemberRepository.vaultsOf(userId)).keys
                .filter { vaultId -> MemberRepository.all(vaultId).keys == setOf(userId) }
            if (!IdentityRepository.lockLive(userId)) return@withoutCaller false
            sole.forEach(VaultRepository::delete)
            MemberRepository.clearEnvelopes(userId)
            IdentityRepository.tombstone(userId, context.clock.now())
            true
        }
    }

    /**
     * Refuses a deleted caller before an adapter reads the request, so a deleted user's every request
     * answers the same; the operations check again inside their transaction, which is what counts.
     *
     * @param caller Authenticated user.
     * @throws CloakException `identity_deleted` when the caller is deleted.
     */
    public fun requireNotDeleted(caller: UserId) {
        if (context.unrecorded { IdentityRepository.isDeleted(caller, lock = false) }) throw CloakException.identityDeleted()
    }

    /**
     * Returns every key version of a user with its statement, oldest first.
     *
     * @param caller Authenticated user.
     * @param userId User.
     * @return The key versions, with the user marked deleted when they are.
     * @throws CloakException `not_found` when the user has no identity.
     */
    public fun userKeys(caller: UserId, userId: UserId): UserKeys = context.operation("getUserKeys") {
        asCaller(caller) {
            val versions = IdentityRepository.statements(listOf(userId))[userId] ?: throw CloakException.notFound("user")
            val hostUserId = IdentityRepository.hostUserIds(listOf(userId))[userId]
            UserKeys(userId, hostUserId, hostUserId == null, versions)
        }
    }

    /**
     * Returns several users' key versions.
     *
     * @param caller Authenticated user.
     * @param userIds 1 to 100 distinct users.
     * @return Key versions of users with an identity, deleted ones marked, and the ids of the others.
     */
    public fun userKeys(caller: UserId, userIds: List<UserId>): UserKeysBatch = context.operation("batchGetUserKeys") {
        Validation.size(userIds, 1..Limits.MAX_BATCH_SIZE, "/userIds")
        Validation.unique(userIds, "/userIds") { it }
        asCaller(caller) {
            val found = IdentityRepository.statements(userIds)
            val hostIds = IdentityRepository.hostUserIds(found.keys)
            UserKeysBatch(
                items = userIds.mapNotNull { id -> found[id]?.let { UserKeys(id, hostIds[id], hostIds[id] == null, it) } },
                missingUserIds = userIds.filterNot(found::containsKey),
            )
        }
    }

    /** Checks the shape of a key version's public keys. */
    private fun checkKeys(keys: PublicKeys) {
        BlobRules.raw(keys.encryptionPublicKey, BlobRules.KEY_BYTES, "/encryptionPublicKey")
        BlobRules.raw(keys.signingPublicKey, BlobRules.KEY_BYTES, "/signingPublicKey")
        BlobRules.raw(keys.recoverySigningPublicKey, BlobRules.KEY_BYTES, "/recoverySigningPublicKey")
        Validation.require(!StrictEd25519.isUnusableKey(keys.signingPublicKey), "/signingPublicKey", "key", "Not a usable Ed25519 key.")
        Validation.require(
            !StrictEd25519.isUnusableKey(keys.recoverySigningPublicKey),
            "/recoverySigningPublicKey",
            "key",
            "Not a usable Ed25519 key.",
        )
    }

    /** Checks Argon2id parameters against the protocol's bounds. */
    private fun checkKdf(kdf: KdfParams) {
        BlobRules.raw(kdf.salt, BlobRules.SALT_BYTES, "/kdf/salt")
        Validation.require(
            kdf.memoryKib in Limits.MIN_KDF_MEMORY_KIB..Limits.MAX_KDF_MEMORY_KIB,
            "/kdf/memoryKib",
            "range",
            "Must be ${Limits.MIN_KDF_MEMORY_KIB} to ${Limits.MAX_KDF_MEMORY_KIB}.",
        )
        Validation.require(
            kdf.iterations in Limits.MIN_KDF_ITERATIONS..Limits.MAX_KDF_ITERATIONS,
            "/kdf/iterations",
            "range",
            "Must be ${Limits.MIN_KDF_ITERATIONS} to ${Limits.MAX_KDF_ITERATIONS}.",
        )
        Validation.require(kdf.parallelism == 1, "/kdf/parallelism", "const", "Must be 1.")
    }

    /** Refuses a signing key any user's key version already uses. */
    private fun requireFreshSigningKey(signingPublicKey: ByteString) {
        if (IdentityRepository.isSigningKeyTaken(signingPublicKey)) {
            throw CloakException(CloakErrorCode.ALREADY_EXISTS, "This signing key belongs to another key version.")
        }
    }

    /** An `identity_version_conflict` at [current]. */
    private fun versionConflict(current: Int): CloakException =
        CloakException(
            CloakErrorCode.IDENTITY_VERSION_CONFLICT,
            "Your keys were replaced on another device.",
            currentVersion = current.toLong(),
        )

    /** Constants of the identity contract. */
    internal companion object {
        /** Furthest ahead an identity deletion statement may expire (`PROTOCOL.md` §5.7). */
        const val MAX_DELETION_VALIDITY_SECONDS: Long = 600

        /** The only crypto suite. */
        const val CRYPTO_SUITE: Int = 1

        /**
         * Verifies a signature strictly or throws.
         *
         * @param publicKey Signer's key.
         * @param message Canonical message.
         * @param signature Signature blob.
         * @param pointer JSON Pointer of the signature, for the detail.
         * @throws CloakException `bad_signature` when it does not verify.
         */
        fun requireSignature(publicKey: ByteString, message: ByteString, signature: ByteString, pointer: String) {
            val refusal = StrictEd25519.check(publicKey, message, signature) ?: return
            throw CloakException(CloakErrorCode.BAD_SIGNATURE, "The signature at $pointer is refused: ${refusal.code}.")
        }
    }
}
