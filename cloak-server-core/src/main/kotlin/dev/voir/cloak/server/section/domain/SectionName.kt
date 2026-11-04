package dev.voir.cloak.server.section.domain

/**
 * Name of one separately encrypted and separately shareable part of a node, such as `general`
 * or `billing`.
 *
 * The name is visible to the server, so it must describe a category, never content.
 */
@JvmInline
public value class SectionName(
    /** Lowercase name of 1 to 64 characters: a letter, then letters, digits or `_`. */
    public val value: String,
) {
    init {
        require(PATTERN.matches(value)) { "Invalid section name" }
    }

    /** Validation rule shared with the `ck_sections__section_name_format` database check. */
    public companion object {
        /** Accepted format, identical to the database check. */
        public val PATTERN: Regex = Regex("^[a-z][a-z0-9_]{0,63}$")
    }
}
