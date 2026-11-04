package dev.voir.cloak.server.identity.domain

import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The host application's own id of a user, exactly as its authentication gives it
 * (`PROTOCOL.md` §5.0): any string of 1 to 255 bytes in UTF-8, compared byte for byte.
 *
 * Its [userId] is the id Cloak derives from it.
 */
public class HostUserId private constructor(
    /** The id as the host gives it. */
    public val value: String,
    /** Its UTF-8 bytes; the input of the derivation. */
    internal val utf8: ByteArray,
) {
    /** The Cloak user id derived from [value]. */
    public val userId: UserId get() = UserId.of(this)

    /** Equal when the ids are; the bytes follow from them. */
    override fun equals(other: Any?): Boolean = other is HostUserId && other.value == value

    /** Hash of the id. */
    override fun hashCode(): Int = value.hashCode()

    /** The id itself. */
    override fun toString(): String = value

    /** Parsing and limits. */
    public companion object {
        /** Most UTF-8 bytes of a host user id. */
        public const val MAX_BYTES: Int = 255

        /**
         * Accepts a host user id.
         *
         * @param value The host's id of the user.
         * @return The id.
         * @throws IllegalArgumentException when [value] is empty, longer than [MAX_BYTES] bytes in
         *   UTF-8, or not well-formed Unicode.
         */
        @JvmStatic
        public fun of(value: String): HostUserId {
            val utf8 = try {
                Charsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value))
                    .let { buffer -> ByteArray(buffer.remaining()).also { buffer.get(it) } }
            } catch (_: CharacterCodingException) {
                throw IllegalArgumentException("A host user id must be well-formed Unicode.")
            }
            require(utf8.size in 1..MAX_BYTES) { "A host user id must be 1 to $MAX_BYTES bytes in UTF-8." }
            return HostUserId(value, utf8)
        }
    }
}
