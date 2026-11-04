package dev.voir.cloak.server.section.domain

/**
 * The names a node entry covers (`PROTOCOL.md` §7.1): every section of the node, or a list.
 */
public sealed interface SectionScope {
    /** Every section of the node, written `*`. */
    public data object All : SectionScope

    /**
     * Some sections, by name.
     *
     * @property names The names, ascending and distinct.
     */
    public data class Names(
        /** The names, ascending and distinct. */
        public val names: List<SectionName>,
    ) : SectionScope

    /** Reading the field. */
    public companion object {
        /**
         * Reads a node entry's `sections`: `*`, or names in ascending byte order, comma-joined,
         * without repeats.
         *
         * @param sections The field.
         * @return The scope, or `null` when the field is malformed.
         */
        public fun parse(sections: String): SectionScope? {
            if (sections == "*") return All
            if (sections.isEmpty()) return null
            val names = sections.split(',')
            // Names are ASCII, so comparing strings compares their UTF-8 bytes.
            val ordered = names.withIndex().all { (index, name) ->
                SectionName.PATTERN.matches(name) && (index == 0 || names[index - 1] < name)
            }
            return if (ordered) Names(names.map(::SectionName)) else null
        }
    }
}
