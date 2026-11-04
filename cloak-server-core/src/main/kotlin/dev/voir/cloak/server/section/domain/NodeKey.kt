package dev.voir.cloak.server.section.domain

/**
 * The application's key for a node, such as the id of the record it holds secrets for
 * (`PROTOCOL.md` §8.1): 1 to 255 bytes of UTF-8. With its owner and home vault it derives the
 * node's id, so every reader knows whose node it is and where it lives.
 *
 * @property value The key as the application gave it.
 */
@JvmInline
public value class NodeKey(
    /** The key as the application gave it. */
    public val value: String,
) {
    init {
        require(isValid(value)) { "A node key has 1 to 255 bytes of UTF-8" }
    }

    /** Validation shared with requests. */
    public companion object {
        /** Most bytes of a node key. */
        public const val MAX_BYTES: Int = 255

        /**
         * Whether a string is a node key.
         *
         * @param value Candidate.
         * @return Whether it has 1 to 255 bytes of well-formed UTF-8.
         */
        public fun isValid(value: String): Boolean {
            val bytes = value.encodeToByteArray(throwOnInvalidSequence = false)
            val wellFormed = runCatching { value.encodeToByteArray(throwOnInvalidSequence = true) }.isSuccess
            return wellFormed && bytes.size in 1..MAX_BYTES
        }
    }
}
