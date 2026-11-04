package dev.voir.cloak.server.vault.domain

/**
 * Kind of a vault log entry (`PROTOCOL.md` §7.2).
 *
 * @property code Stable value stored in the database and sent on the wire.
 * @property protocolCode Value in signed messages (`PROTOCOL.md` §3).
 */
public enum class LogEntryKind(
    /** Stable persisted and wire value; never reuse or rename one. */
    public val code: String,
    /** Value in signed messages. */
    internal val protocolCode: Int,
) {
    /** The vault was created, with its author as owner; always `seq` 1. */
    VAULT_CREATED("vault_created", 1),

    /** A user became a member with a role and committed keys. */
    MEMBER_ADDED("member_added", 2),

    /** A member's role changed. */
    MEMBER_ROLE_SET("member_role_set", 3),

    /** A member was removed in a rotation, or left. */
    MEMBER_REMOVED("member_removed", 4),

    /** A member moved to a new version of their identity keys. */
    MEMBER_KEYS_REPLACED("member_keys_replaced", 5),

    /** The vault key moved to its next version. */
    KEY_ROTATED("key_rotated", 6),

    /** A member created a node in this vault, its home (`PROTOCOL.md` §7.7). */
    NODE_CREATED("node_created", 7),

    /** A node's owner shared some of its sections, or all, into this vault. */
    NODE_SHARED("node_shared", 8),

    /** Shared sections of a node were taken back. */
    NODE_UNSHARED("node_unshared", 9),

    /** An owner deleted the vault; the last entry its log ever has. */
    VAULT_DELETED("vault_deleted", 10),
    ;

    /** Lookup of kinds by persisted code. */
    public companion object {
        /**
         * Finds the kind stored under [code].
         *
         * @param code Persisted or wire value.
         * @return The matching kind.
         * @throws IllegalArgumentException When the code is unknown.
         */
        public fun fromCode(code: String): LogEntryKind =
            requireNotNull(entries.firstOrNull { it.code == code }) { "Unknown log entry kind: $code" }
    }
}
