package dev.voir.cloak.server.vault

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.DatabaseKeyDirectory
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.vault.domain.AddMemberCommand
import dev.voir.cloak.server.vault.domain.DeliverEnvelopeCommand
import dev.voir.cloak.server.vault.domain.LeaveVaultCommand
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.RecordKeyReplacementCommand
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.RotateVaultCommand
import dev.voir.cloak.server.vault.domain.SetMemberRoleCommand
import dev.voir.cloak.server.vault.domain.Vault
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultRotation
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.MemberRow
import dev.voir.cloak.server.vault.persistence.VaultKeyRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import dev.voir.cloak.server.vault.persistence.WritePauseRepository
import dev.voir.cloak.server.vault.persistence.WritePauseRow
import dev.voir.cloak.server.section.secondsUntil
import dev.voir.cloak.server.CloakSettings
import kotlin.time.Instant
import kotlin.time.toKotlinDuration

/**
 * Who belongs to a vault: adding members, roles, envelopes, leaving, rotation and key
 * replacements (`/vaults/{vaultId}/members`, `departures`, `rotations`, `key-replacements`).
 *
 * Every operation locks the vault's row first, verifies its signed entries against the vault's
 * state with the same rules every member's client applies, and stores them in one transaction.
 *
 * @property context Database and clock.
 */
public class MemberOperations internal constructor(
    private val context: CloakContext,
) {
    /**
     * Adds a member with a role, the current vault key sealed to their newest key version, and the
     * signed `member_added` entry.
     *
     * @param caller Authenticated user; an admin, or an owner to add an owner.
     * @param vaultId The vault.
     * @param command The member, role, envelope and entry.
     * @return The vault as the caller sees it afterwards.
     * @throws CloakException `not_found`, `identity_required`, `identity_deleted` when the user is
     *   deleted, `already_exists`, `vault_key_version_mismatch`, `validation_failed` (rule `max_members`),
     *   `too_many_invitations` when the user has too many vaults not accepted yet, and the errors of
     *   [LogAppender.verify].
     */
    public fun add(caller: UserId, vaultId: VaultId, command: AddMemberCommand): Vault = context.operation("addMember") {
        BlobRules.envelope(command.keyEnvelope, "/keyEnvelope")
        val log = command.log
        requireLog(
            log.kind == LogEntryKind.MEMBER_ADDED && log.subjectUserId == command.userId &&
                log.role == command.role && log.subjectKeyVersion == command.userKeyVersion,
        )
        asCaller(caller) {
            val view = VaultAccess.lockForMember(caller, vaultId)
            val keys = DatabaseKeyDirectory()
            keys.currentVersion(command.userId) ?: throw CloakException.identityRequired("The user")
            // The directory holds a shared lock on the user's row, so an erasure cannot commit after this.
            if (IdentityRepository.isDeleted(command.userId, lock = false)) throw CloakException.identityDeleted("The user")
            if (command.userId in view.members) throw CloakException(CloakErrorCode.ALREADY_EXISTS, "The user is already a member.")
            Validation.require(
                view.members.size < Limits.MAX_MEMBERS_PER_VAULT,
                "/userId",
                "max_members",
                "The vault has ${Limits.MAX_MEMBERS_PER_VAULT} members already.",
            )
            requireCurrentKey(view, command.keyVersion)
            val appender = LogAppender(keys, context.clock.now(), this)
            val request = appender.verify(LogAppender.stateOf(view.vault, view.members), caller, listOf(log), emptyList(), "/log")
            val membership = checkNotNull(request.after.members[command.userId])
            // Acceptance is the server's help against being added unasked (§12.4): the person sees the
            // vault once they accept it, or at once when they accept everything from the caller.
            val accepted = MemberRepository.acceptsFrom(command.userId, caller)
            if (!accepted && MemberRepository.pendingCount(command.userId) >= context.settings.maxPendingInvitations) {
                throw CloakException(
                    CloakErrorCode.TOO_MANY_INVITATIONS,
                    "The user has ${context.settings.maxPendingInvitations} vaults they have not accepted yet.",
                )
            }
            // One inviter cannot use up the user's whole limit.
            if (!accepted && MemberRepository.pendingCount(command.userId, caller) >= context.settings.maxPendingInvitationsPerInviter) {
                throw CloakException(
                    CloakErrorCode.TOO_MANY_INVITATIONS,
                    "The user has ${context.settings.maxPendingInvitationsPerInviter} vaults from you they have not accepted yet.",
                )
            }
            MemberRepository.insert(
                MemberRow(
                    vaultId,
                    command.userId,
                    membership,
                    command.keyEnvelope,
                    view.vault.keyVersion,
                    context.clock.now(),
                    accepted = accepted,
                    addedByUserId = caller,
                ),
            )
            appender.store(request)
            vaultFor(caller, vaultId)
        }
    }

    /**
     * Changes a member's role with a signed `member_role_set`; taking away the right to write
     * carries a checkpoint.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param userId The member.
     * @param command The role, entry and the writes its checkpoint leaves out.
     * @return The vault as the caller sees it afterwards.
     * @throws CloakException `not_found` and the errors of [LogAppender.verify].
     */
    public fun setRole(caller: UserId, vaultId: VaultId, userId: UserId, command: SetMemberRoleCommand): Vault = context.operation("setMemberRole") {
        val log = command.log
        requireLog(log.kind == LogEntryKind.MEMBER_ROLE_SET && log.subjectUserId == userId && log.role == command.role)
        asCaller(caller, CloakContext.Budget.CHECKPOINT) {
            val view = VaultAccess.lockForMember(caller, vaultId)
            val target = view.members[userId] ?: throw CloakException.notFound("member")
            val appender = LogAppender(DatabaseKeyDirectory(), context.clock.now(), this)
            val request = appender.verify(LogAppender.stateOf(view.vault, view.members), caller, listOf(log), command.leftOut, "/log")
            MemberRepository.updateMembership(vaultId, userId, checkNotNull(request.after.members[target.userId]))
            appender.store(request)
            vaultFor(caller, vaultId)
        }
    }

    /**
     * Stores a new envelope of the current vault key for a member, sealed to their committed key
     * version (`PROTOCOL.md` §6.3). Unsigned: the member checks the key against its commitment.
     *
     * @param caller Authenticated user; the member themselves or an admin.
     * @param vaultId The vault.
     * @param userId The member.
     * @param command Key versions and the envelope.
     * @throws CloakException `not_found`, `role_required`, `vault_key_version_mismatch`,
     *   `validation_failed` when the envelope is not for the committed key version,
     *   `identity_version_conflict` when that version is superseded, `identity_deleted` when the
     *   member is deleted (`PROTOCOL.md` §5.7).
     */
    public fun deliverEnvelope(caller: UserId, vaultId: VaultId, userId: UserId, command: DeliverEnvelopeCommand) {
        context.operation("deliverEnvelope") {
            BlobRules.envelope(command.keyEnvelope, "/keyEnvelope")
            asCaller(caller) {
                val view = VaultAccess.lockForMember(caller, vaultId)
                val target = view.members[userId] ?: throw CloakException.notFound("member")
                if (userId != caller) view.requireRole(Role.ADMIN, "deliver another member's envelope")
                // A key-share lock, so an erasure cannot commit between this check and the envelope.
                if (IdentityRepository.isDeleted(userId, lock = true)) throw CloakException.identityDeleted("The member")
                requireCurrentKey(view, command.keyVersion)
                Validation.require(
                    command.userKeyVersion == target.membership.userKeyVersion,
                    "/userKeyVersion",
                    "committed",
                    "Must be the member's committed key version, ${target.membership.userKeyVersion}.",
                )
                if (DatabaseKeyDirectory().isSuperseded(userId, target.membership.userKeyVersion)) {
                    throw CloakException(
                        CloakErrorCode.IDENTITY_VERSION_CONFLICT,
                        "The member replaced these keys; they record the replacement before anyone delivers to them.",
                        currentVersion = target.membership.userKeyVersion.toLong(),
                    )
                }
                MemberRepository.setEnvelope(vaultId, userId, command.keyEnvelope, view.vault.keyVersion)
            }
        }
    }

    /**
     * The caller leaves a vault with a signed `member_removed`, with a checkpoint when they could
     * write. The key is not rotated; admins see that a rotation is due.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param command The entry and the writes its checkpoint leaves out.
     * @throws CloakException `not_found` and the errors of [LogAppender.verify].
     */
    public fun leave(caller: UserId, vaultId: VaultId, command: LeaveVaultCommand) {
        context.operation("leaveVault") {
            val log = command.log
            requireLog(log.kind == LogEntryKind.MEMBER_REMOVED && log.subjectUserId == caller)
            asCaller(caller, CloakContext.Budget.CHECKPOINT) {
                val view = VaultAccess.lockForMember(caller, vaultId)
                val appender = LogAppender(DatabaseKeyDirectory(), context.clock.now(), this)
                val request = appender.verify(LogAppender.stateOf(view.vault, view.members), caller, listOf(log), command.leftOut, "/log")
                MemberRepository.delete(vaultId, caller)
                appender.store(request)
            }
        }
    }

    /**
     * Rotates the vault key, removing members (`PROTOCOL.md` §7.4): zero or more `member_removed`,
     * then `key_rotated` with its commitment and checkpoint; the previous key wrapped by the new
     * one; and an envelope for every remaining member whose key version is not superseded and who is
     * not deleted (`PROTOCOL.md` §5.7).
     *
     * @param caller Authenticated user; an admin, or an owner to remove an owner.
     * @param vaultId The vault.
     * @param command The new key, envelopes, entries and the writes the checkpoint leaves out.
     * @return The vault as the caller sees it afterwards.
     * @throws CloakException `not_found`, `vault_key_version_mismatch`, `recipients_mismatch`, and
     *   the errors of [LogAppender.verify].
     */
    public fun rotate(caller: UserId, vaultId: VaultId, command: RotateVaultCommand): Vault = context.operation("rotateVault") {
        checkRotationShape(command, "")
        asCaller(caller, CloakContext.Budget.CHECKPOINT) { rotateLocked(caller, vaultId, command, "") }
    }

    /**
     * Rotates several vaults in one transaction, all or none (`PROTOCOL.md` §12.4): the request
     * that removes people from a group of vaults so nobody is left half removed. The vaults are
     * locked in id order, then each rotation is checked and applied exactly as [rotate] does it.
     *
     * @param caller Authenticated user; an admin of every vault, or an owner to remove an owner.
     * @param rotations 1 to 100 rotations of distinct vaults.
     * @return Every vault as the caller sees it afterwards, in request order.
     * @throws CloakException The errors of [rotate] for the first rotation refused, naming its
     *   vault; nothing is applied.
     */
    public fun rotateMany(caller: UserId, rotations: List<VaultRotation>): List<Vault> = context.operation("batchRotateVaults") {
        Validation.size(rotations, 1..Limits.MAX_BATCH_SIZE, "/items")
        Validation.unique(rotations, "/items") { it.vaultId }
        rotations.forEachIndexed { index, rotation ->
            inVault(rotation.vaultId) { checkRotationShape(rotation.command, "/items/$index") }
        }
        asCaller(caller, CloakContext.Budget.CHECKPOINT) {
            val ids = rotations.map { it.vaultId }
            val member = MemberRepository.roles(caller, ids).keys
            ids.firstOrNull { it !in member }?.let { throw CloakException.notFound("vault").forVault(it) }
            VaultRepository.lock(ids)
            rotations.mapIndexed { index, rotation ->
                inVault(rotation.vaultId) { rotateLocked(caller, rotation.vaultId, rotation.command, "/items/$index") }
            }
        }
    }

    /** Checks a rotation's shape, before any transaction; [prefix] leads every JSON Pointer. */
    private fun checkRotationShape(command: RotateVaultCommand, prefix: String) {
        Validation.size(command.log, 1..Limits.MAX_ROTATION_ENTRIES, "$prefix/log")
        Validation.size(command.envelopes, 0..Limits.MAX_MEMBERS_PER_VAULT, "$prefix/envelopes")
        Validation.unique(command.envelopes, "$prefix/envelopes") { it.userId }
        command.envelopes.forEachIndexed { index, envelope -> BlobRules.envelope(envelope.keyEnvelope, "$prefix/envelopes/$index/keyEnvelope") }
        BlobRules.wrappedKey(command.previousWrappedKey, "$prefix/previousWrappedKey")
        val last = command.log.last()
        requireLog(last.kind == LogEntryKind.KEY_ROTATED && last.keyVersion == command.keyVersion, "$prefix/log/${command.log.lastIndex}")
    }

    /** Checks and applies one rotation inside the caller's transaction; [prefix] leads every JSON Pointer. */
    private fun CloakContext.OperationScope.rotateLocked(caller: UserId, vaultId: VaultId, command: RotateVaultCommand, prefix: String): Vault {
        val last = command.log.last()
        val view = VaultAccess.lockForMember(caller, vaultId)
        requireCurrentKey(view, command.keyVersion - 1)
        val keys = DatabaseKeyDirectory()
        val appender = LogAppender(keys, context.clock.now(), this)
        val request = appender.verify(
            LogAppender.stateOf(view.vault, view.members),
            caller,
            command.log,
            command.leftOut,
            "$prefix/log",
            isList = true,
        )
        val remaining = request.after.members
        // Key-share locks: no erasure commits between choosing the recipients and sealing to them.
        val deleted = IdentityRepository.deleted(remaining.keys, lock = true)
        val recipients = remaining.filter { (userId, membership) ->
            userId !in deleted && !keys.isSuperseded(userId, membership.userKeyVersion)
        }
        val envelopes = command.envelopes.associateBy { it.userId }
        val matches = envelopes.keys == recipients.keys &&
            envelopes.all { (userId, envelope) -> envelope.userKeyVersion == recipients.getValue(userId).userKeyVersion }
        if (!matches) {
            throw CloakException(
                CloakErrorCode.RECIPIENTS_MISMATCH,
                "Seal the new key to exactly the ${recipients.size} remaining members whose keys are current and who are not deleted.",
            )
        }
        val now = context.clock.now()
        VaultKeyRepository.insert(vaultId, command.keyVersion, checkNotNull(last.keyCommitment), command.previousWrappedKey, now)
        (view.members.keys - remaining.keys).forEach { MemberRepository.delete(vaultId, it) }
        remaining.keys.forEach { userId ->
            MemberRepository.setEnvelope(vaultId, userId, envelopes[userId]?.keyEnvelope, envelopes[userId]?.let { command.keyVersion })
        }
        appender.store(request)
        return vaultFor(caller, vaultId)
    }

    /** Runs [block], naming [vaultId] in any refusal it throws. */
    private inline fun <T> inVault(vaultId: VaultId, block: () -> T): T =
        try {
            block()
        } catch (refusal: CloakException) {
            throw refusal.forVault(vaultId)
        }

    /**
     * Records the caller's key replacement in a vault (`PROTOCOL.md` §5.6): a signed
     * `member_keys_replaced` with the new keys, a checkpoint when the caller could write, and the
     * current vault key sealed to the new keys, or none for an admin to deliver. The old keys lose
     * every right in the vault.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @param command The entry, envelope and the writes the checkpoint leaves out.
     * @return The vault as the caller sees it afterwards.
     * @throws CloakException `not_found` and the errors of [LogAppender.verify].
     */
    public fun recordKeyReplacement(caller: UserId, vaultId: VaultId, command: RecordKeyReplacementCommand): Vault = context.operation("recordKeyReplacement") {
        command.keyEnvelope?.let { BlobRules.envelope(it, "/keyEnvelope") }
        val log = command.log
        requireLog(log.kind == LogEntryKind.MEMBER_KEYS_REPLACED && log.subjectUserId == caller)
        asCaller(caller, CloakContext.Budget.CHECKPOINT) {
            val view = VaultAccess.lockForMember(caller, vaultId)
            val appender = LogAppender(DatabaseKeyDirectory(), context.clock.now(), this)
            val request = appender.verify(LogAppender.stateOf(view.vault, view.members), caller, listOf(log), command.leftOut, "/log")
            MemberRepository.updateMembership(vaultId, caller, checkNotNull(request.after.members[caller]))
            MemberRepository.setEnvelope(vaultId, caller, command.keyEnvelope, command.keyEnvelope?.let { view.vault.keyVersion })
            appender.store(request)
            vaultFor(caller, vaultId)
        }
    }

    /**
     * Pauses section writes to vaults for [CloakSettings.writePause], all or none, so a request
     * with a checkpoint that follows cannot be outrun by writes (`PROTOCOL.md` §7.5). The pause ends
     * when a request of the caller carrying a checkpoint for the vault is applied, on
     * [releaseWritePauses], or when it runs out. It is the server's help to honest members only:
     * nothing a client accepts depends on it.
     *
     * An admin's pause replaces anyone's. A member who is not an admin may pause a vault only where
     * nobody else's pause holds it, and only once per [CloakSettings.writePauseInterval], renewals
     * included, so no member can keep a vault paused or keep an admin from pausing it.
     *
     * @param caller Authenticated user; an editor or stronger of every vault.
     * @param vaultIds 1 to 100 distinct vaults.
     * @return When the pauses end.
     * @throws CloakException `not_found`, `role_required` (editor), `pause_held` when another
     *   member's pause holds a vault, `rate_limited` when the caller paused it too recently; each
     *   names its vault.
     */
    public fun pauseWrites(caller: UserId, vaultIds: List<VaultId>): Instant = context.operation("pauseWrites") {
        Validation.size(vaultIds, 1..Limits.MAX_BATCH_SIZE, "/vaultIds")
        Validation.unique(vaultIds, "/vaultIds") { it }
        asCaller(caller) {
            // Membership first, without locks: a non-member cannot hold other vaults locked.
            if (!MemberRepository.roles(caller, vaultIds).keys.containsAll(vaultIds)) throw CloakException.notFound("vault")
            val vaults = VaultRepository.lock(vaultIds)
            val roles = MemberRepository.roles(caller, vaultIds)
            val now = context.clock.now()
            val until = now + context.settings.writePause.toKotlinDuration()
            val interval = context.settings.writePauseInterval.toKotlinDuration()
            val asAdmin = vaultIds.associateWith { vaultId ->
                val vault = vaults[vaultId]?.takeUnless { it.isDeleted } ?: throw CloakException.notFound("vault")
                val role = roles[vaultId] ?: throw CloakException.notFound("vault")
                if (!role.includes(Role.EDITOR)) throw CloakException.roleRequired(Role.EDITOR, "pause writes").forVault(vaultId)
                val admin = role.includes(Role.ADMIN)
                val held = vault.pause?.takeIf { it.holdsAt(now) && it.userId != caller }
                if (held != null && !admin) {
                    throw CloakException(
                        CloakErrorCode.PAUSE_HELD,
                        "Another member's write pause holds the vault.",
                        retryAfterSeconds = secondsUntil(now, held.until),
                    ).forVault(vaultId)
                }
                val last = if (admin) null else WritePauseRepository.lastPause(vaultId, caller)
                if (last != null && last + interval > now) {
                    throw CloakException.rateLimited("You paused this vault's writes recently.", secondsUntil(now, last + interval))
                        .forVault(vaultId)
                }
                admin
            }
            asAdmin.forEach { (vaultId, admin) ->
                VaultRepository.setPause(vaultId, WritePauseRow(caller, admin, until))
                if (!admin) WritePauseRepository.record(vaultId, caller, now)
            }
            until
        }
    }

    /**
     * Ends the caller's own write pauses of vaults; vaults without one are left as they are, and
     * nothing tells whether they exist.
     *
     * @param caller Authenticated user.
     * @param vaultIds 1 to 100 distinct vaults.
     */
    public fun releaseWritePauses(caller: UserId, vaultIds: List<VaultId>) {
        context.operation("releaseWritePauses") {
            Validation.size(vaultIds, 1..Limits.MAX_BATCH_SIZE, "/vaultIds")
            Validation.unique(vaultIds, "/vaultIds") { it }
            asCaller(caller) { VaultRepository.endPausesOf(vaultIds, caller) }
        }
    }

    /**
     * Accepts a vault the caller was added to (`PROTOCOL.md` §12.4): it is listed for them and the
     * host counts them for its access checks. Unsigned, the server's help; the log alone decides
     * what a member may read and write.
     *
     * @param caller Authenticated user.
     * @param vaultId The vault.
     * @throws CloakException `not_found` unless the caller is a member of a vault not deleted.
     */
    public fun accept(caller: UserId, vaultId: VaultId) {
        context.operation("acceptVault") {
            asCaller(caller) {
                VaultAccess.readAsMember(caller, vaultId)
                MemberRepository.accept(vaultId, caller)
            }
        }
    }

    /**
     * Accepts every vault one person added the caller to, and every one they add later.
     *
     * @param caller Authenticated user.
     * @param inviterUserId The person whose vaults the caller accepts.
     */
    public fun acceptInviter(caller: UserId, inviterUserId: UserId) {
        context.operation("acceptInviter") {
            asCaller(caller) { MemberRepository.acceptFrom(caller, inviterUserId, context.clock.now()) }
        }
    }

    /** Requires a request's key version to be the vault's current one. */
    private fun requireCurrentKey(view: VaultView, keyVersion: Int) {
        if (keyVersion != view.vault.keyVersion) {
            throw CloakException(
                CloakErrorCode.VAULT_KEY_VERSION_MISMATCH,
                "The vault key is at version ${view.vault.keyVersion}.",
                currentVersion = view.vault.keyVersion.toLong(),
            )
        }
    }

    /** Requires an entry to describe exactly what the request does. */
    private fun requireLog(matches: Boolean, pointer: String = "/log") {
        Validation.require(matches, pointer, "log_mismatch", "Must describe exactly what the request does.")
    }

    /** The vault as the caller sees it, read again after the request's writes. */
    private fun vaultFor(caller: UserId, vaultId: VaultId): Vault {
        val vault = checkNotNull(VaultRepository.find(vaultId))
        return VaultAccess.toVault(vault, checkNotNull(MemberRepository.find(vaultId, caller)))
    }
}
