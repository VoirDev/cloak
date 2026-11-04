package dev.voir.cloak.server.error

import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId

/**
 * An expected failure of a Cloak operation, carrying everything an adapter needs to render the
 * RFC 9457 problem.
 *
 * Operations throw it inside their transaction, so nothing of the failed request is stored.
 * [detail] never contains secrets or ciphertext.
 *
 * @property code Stable error code.
 * @property detail Explanation of this occurrence.
 * @property currentVersion Current version for `version_conflict`, `vault_key_version_mismatch`,
 *   `credentials_version_conflict` and `identity_version_conflict`; head `seq` for `log_conflict`
 *   and `stale_head`; `null` otherwise.
 * @property fieldErrors Violated rules for `validation_failed`; empty otherwise.
 * @property role Role the caller needs, for `role_required`; `null` otherwise.
 * @property retryAfterSeconds Seconds to wait before retrying, for `busy` and `rate_limited`; `null`
 *   otherwise.
 * @property vaultId The vault a batch request was refused for; `null` otherwise.
 */
public class CloakException(
    /** Stable error code. */
    public val code: CloakErrorCode,
    /** Explanation of this occurrence. */
    public val detail: String,
    /** Current version for the version-conflict codes. */
    public val currentVersion: Long? = null,
    /** Violated rules for `validation_failed`. */
    public val fieldErrors: List<FieldError> = emptyList(),
    /** Role the caller needs, for `role_required`. */
    public val role: Role? = null,
    /** Seconds to wait before retrying, for `busy` and `rate_limited`. */
    public val retryAfterSeconds: Int? = null,
    /** The vault a batch request was refused for. */
    public val vaultId: VaultId? = null,
) : RuntimeException("${code.code}: $detail") {
    /**
     * Returns this refusal naming the vault of a batch request it came from.
     *
     * @param vault The vault.
     * @return The same refusal with [vaultId] set.
     */
    internal fun forVault(vault: VaultId): CloakException =
        CloakException(code, detail, currentVersion, fieldErrors, role, retryAfterSeconds, vault)

    /** Factories for the failures several operations share. */
    internal companion object {
        /**
         * A single invalid field.
         *
         * @param pointer JSON Pointer to the value.
         * @param rule Violated rule.
         * @param message Explanation.
         * @return A `validation_failed` exception.
         */
        fun invalid(pointer: String, rule: String, message: String): CloakException =
            CloakException(
                code = CloakErrorCode.VALIDATION_FAILED,
                detail = "The request has 1 invalid field.",
                fieldErrors = listOf(FieldError(pointer, rule, message)),
            )

        /**
         * A role too weak for the operation.
         *
         * @param needed Weakest role that may do it.
         * @param action What the caller tried, for the detail.
         * @return A `role_required` exception.
         */
        fun roleRequired(needed: Role, action: String): CloakException =
            CloakException(CloakErrorCode.ROLE_REQUIRED, "You need the ${needed.code} role to $action.", role = needed)

        /**
         * A missing or hidden resource.
         *
         * @param what Kind of resource, for the detail.
         * @return A `not_found` exception.
         */
        fun notFound(what: String): CloakException =
            CloakException(CloakErrorCode.NOT_FOUND, "The $what does not exist or is not visible to you.")

        /**
         * The caller, or a user the request names, has no identity.
         *
         * @param who Whose identity is missing, for the detail.
         * @return An `identity_required` exception.
         */
        fun identityRequired(who: String = "You"): CloakException =
            CloakException(CloakErrorCode.IDENTITY_REQUIRED, "$who must register an identity first.")

        /**
         * The caller, or a user the request names, is deleted.
         *
         * @param who Who is deleted, for the detail.
         * @return An `identity_deleted` exception.
         */
        fun identityDeleted(who: String = "Your identity"): CloakException =
            CloakException(CloakErrorCode.IDENTITY_DELETED, "$who was deleted.")

        /**
         * The database could not finish the request in time.
         *
         * @param retryAfterSeconds Seconds to wait before retrying.
         * @return A `busy` exception.
         */
        fun busy(retryAfterSeconds: Int): CloakException =
            CloakException(
                CloakErrorCode.BUSY,
                "The vault is busy or the request ran out of time; nothing was applied. Retry later.",
                retryAfterSeconds = retryAfterSeconds,
            )

        /**
         * Section writes to a vault are paused for a checkpoint (`PROTOCOL.md` §7.5).
         *
         * @param retryAfterSeconds Seconds until the pause ends.
         * @return A `busy` exception.
         */
        fun paused(retryAfterSeconds: Int): CloakException =
            CloakException(
                CloakErrorCode.BUSY,
                "Writes to the vault are paused for a checkpoint; nothing was applied. Retry when it ends.",
                retryAfterSeconds = retryAfterSeconds,
            )

        /**
         * The caller asked too often.
         *
         * @param detail What was asked too often.
         * @param retryAfterSeconds Seconds to wait before asking again.
         * @return A `rate_limited` exception.
         */
        fun rateLimited(detail: String, retryAfterSeconds: Int): CloakException =
            CloakException(CloakErrorCode.RATE_LIMITED, detail, retryAfterSeconds = retryAfterSeconds)
    }
}
