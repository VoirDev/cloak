package dev.voir.cloak.server.section.domain

/**
 * App-defined node type, such as `project` or `server.user`. Visible to the server.
 */
@JvmInline
public value class NodeType(
    /** Lowercase type of 1 to 64 characters: a letter, then letters, digits, `_`, `.` or `-`. */
    public val value: String,
) {
    init {
        require(PATTERN.matches(value)) { "Invalid node type" }
    }

    /** Validation rule shared with the `ck_sections__node_type_format` database check. */
    public companion object {
        /** Accepted format, identical to the database check. */
        public val PATTERN: Regex = Regex("^[a-z][a-z0-9_.-]{0,63}$")
    }
}
