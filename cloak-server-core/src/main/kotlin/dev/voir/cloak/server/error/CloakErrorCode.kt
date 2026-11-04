package dev.voir.cloak.server.error

/**
 * Stable error codes of the Cloak API (`ErrorCode` in the OpenAPI spec).
 *
 * Adapters render each one as an RFC 9457 problem with type `urn:cloak:problem:<code>`.
 *
 * @property code Stable wire value; never rename or reuse one.
 * @property status HTTP status the API contract assigns to this code.
 * @property title Short summary, the same for every occurrence.
 */
public enum class CloakErrorCode(
    /** Stable wire value. */
    public val code: String,
    /** HTTP status assigned by the API contract. */
    public val status: Int,
    /** Short summary for the problem `title`. */
    public val title: String,
) {
    /** The request breaks a validation rule; see [CloakException.fieldErrors]. */
    VALIDATION_FAILED("validation_failed", 400, "Validation failed"),

    /** A signature does not verify against the signer's key. */
    BAD_SIGNATURE("bad_signature", 400, "Bad signature"),

    /** A log entry breaks a rule of `PROTOCOL.md` §7; [CloakException.detail] names it. */
    LOG_REJECTED("log_rejected", 400, "Log entry rejected"),

    /** Unknown blob format version or crypto suite. */
    UNSUPPORTED_FORMAT("unsupported_format", 400, "Unsupported format"),

    /** A format version that is read-only now. */
    DEPRECATED_FORMAT("deprecated_format", 400, "Deprecated format"),

    /** No valid host session. Raised by adapters, never by the core. */
    UNAUTHENTICATED("unauthenticated", 401, "Authentication required"),

    /** The caller's role is too weak; see [CloakException.role] for the one needed. */
    ROLE_REQUIRED("role_required", 403, "Stronger role required"),

    /** Missing, or not visible to the caller. */
    NOT_FOUND("not_found", 404, "Not found"),

    /** The caller, or the user to add, has no identity yet. */
    IDENTITY_REQUIRED("identity_required", 404, "Identity required"),

    /** A resource with this id exists, or the user is already a member. */
    ALREADY_EXISTS("already_exists", 409, "Already exists"),

    /** The section's data version moved on; see [CloakException.currentVersion]. */
    VERSION_CONFLICT("version_conflict", 409, "Version conflict"),

    /** The vault log moved on since the head a write cites; see [CloakException.currentVersion]. */
    STALE_HEAD("stale_head", 409, "Stale log head"),

    /** The vault key rotated; see [CloakException.currentVersion]. */
    VAULT_KEY_VERSION_MISMATCH("vault_key_version_mismatch", 409, "Vault key version mismatch"),

    /** The log moved on; see [CloakException.currentVersion] for its head `seq`. */
    LOG_CONFLICT("log_conflict", 409, "Log conflict"),

    /** The checkpoint does not match the stored latest writes. */
    CHECKPOINT_CONFLICT("checkpoint_conflict", 409, "Checkpoint conflict"),

    /** A rotation must reseal to exactly the remaining members. */
    RECIPIENTS_MISMATCH("recipients_mismatch", 409, "Recipients mismatch"),

    /** Credentials changed on another device. */
    CREDENTIALS_VERSION_CONFLICT("credentials_version_conflict", 409, "Credentials version conflict"),

    /** Identity keys were replaced on another device, or a key version is superseded. */
    IDENTITY_VERSION_CONFLICT("identity_version_conflict", 409, "Identity version conflict"),

    /** The caller is a member of a vault, so their identity cannot be deleted yet. */
    IDENTITY_IN_VAULTS("identity_in_vaults", 409, "Identity in vaults"),

    /** Someone else's write pause holds the vault, and the caller may not replace it. */
    PAUSE_HELD("pause_held", 409, "Pause held"),

    /** The person has as many vaults awaiting their acceptance as allowed (`PROTOCOL.md` §12.4). */
    TOO_MANY_INVITATIONS("too_many_invitations", 409, "Too many invitations"),

    /** The caller, or the user the request names, is deleted (`PROTOCOL.md` §5.7). */
    IDENTITY_DELETED("identity_deleted", 410, "Identity deleted"),

    /** The body or a section is larger than the limit. */
    PAYLOAD_TOO_LARGE("payload_too_large", 413, "Payload too large"),

    /** The host's request guard refused the request; see [CloakException.retryAfterSeconds]. */
    RATE_LIMITED("rate_limited", 429, "Too many requests"),

    /** The vault is busy or the request ran out of database time; see [CloakException.retryAfterSeconds]. */
    BUSY("busy", 503, "Busy"),

    /** Unexpected failure. Raised by adapters for any other exception. */
    INTERNAL_ERROR("internal_error", 500, "Internal error"),
}
