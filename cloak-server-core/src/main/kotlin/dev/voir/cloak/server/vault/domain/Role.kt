package dev.voir.cloak.server.vault.domain

/**
 * Role of a member in a vault, weakest first; each role includes every weaker one.
 *
 * @property code Stable value stored in the database and sent on the wire.
 * @property protocolCode Value in signed messages (`PROTOCOL.md` §3).
 */
public enum class Role(
    /** Stable persisted and wire value; never reuse or rename one. */
    public val code: String,
    /** Value in signed messages. */
    internal val protocolCode: Int,
) {
    /** Reads the vault, its log and its sections; may leave. */
    VIEWER("viewer", 1),

    /** Also writes, deletes and moves sections in the vault. */
    EDITOR("editor", 2),

    /** Also adds members, changes roles below owner, removes members and rotates the key. */
    ADMIN("admin", 3),

    /** Also appoints and removes owners and deletes the vault. */
    OWNER("owner", 4),
    ;

    /**
     * Tells whether this role includes [other].
     *
     * @param other Role needed.
     * @return `true` when this role is [other] or stronger.
     */
    public fun includes(other: Role): Boolean = ordinal >= other.ordinal

    /** Lookup of roles by persisted code. */
    public companion object {
        /**
         * Finds the role stored under [code].
         *
         * @param code Persisted or wire value.
         * @return The matching role.
         * @throws IllegalArgumentException When the code is unknown.
         */
        public fun fromCode(code: String): Role =
            requireNotNull(entries.firstOrNull { it.code == code }) { "Unknown role: $code" }
    }
}
