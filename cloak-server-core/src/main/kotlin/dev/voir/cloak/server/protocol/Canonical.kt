package dev.voir.cloak.server.protocol

import kotlinx.io.bytestring.ByteString
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlin.uuid.Uuid

/**
 * Builder of canonical messages (`PROTOCOL.md` §3): typed fields concatenated without separators.
 *
 * The server rebuilds signed messages with it from request fields and stored state, so its output
 * must match the clients' byte for byte; the shared test vectors check that.
 */
internal class Canonical {
    /** Bytes written so far. */
    private val out = ByteArrayOutputStream()

    /**
     * Appends the domain label; always the first field.
     *
     * @param value Label starting with `cloak/v1/`.
     * @return This builder.
     */
    fun label(value: String): Canonical {
        require(value.startsWith("cloak/v1/")) { "Labels start with cloak/v1/" }
        return str(value)
    }

    /**
     * Appends a string as a 2-byte big-endian length and its UTF-8 bytes, without normalizing it.
     *
     * @param value String of at most 65 535 UTF-8 bytes.
     * @return This builder.
     */
    fun str(value: String): Canonical {
        val bytes = value.encodeToByteArray()
        require(bytes.size <= 0xFFFF) { "String too long" }
        out.write(bytes.size ushr 8)
        out.write(bytes.size and 0xFF)
        out.write(bytes)
        return this
    }

    /**
     * Appends one unsigned byte.
     *
     * @param value Value in `0..255`.
     * @return This builder.
     */
    fun u8(value: Int): Canonical {
        require(value in 0..0xFF) { "u8 out of range" }
        out.write(value)
        return this
    }

    /**
     * Appends a flag: one byte, 0 or 1.
     *
     * @param value The flag.
     * @return This builder.
     */
    fun flag(value: Boolean): Canonical = u8(if (value) 1 else 0)

    /**
     * Appends an unsigned 32-bit big-endian integer.
     *
     * @param value Non-negative value.
     * @return This builder.
     */
    fun u32(value: Int): Canonical {
        require(value >= 0) { "u32 out of range" }
        for (shift in 24 downTo 0 step 8) out.write((value ushr shift) and 0xFF)
        return this
    }

    /**
     * Appends an unsigned 64-bit big-endian integer.
     *
     * @param value Non-negative value.
     * @return This builder.
     */
    fun u64(value: Long): Canonical {
        require(value >= 0) { "u64 out of range" }
        return u64(value.toULong())
    }

    /**
     * Appends an unsigned 64-bit big-endian integer.
     *
     * @param value Any unsigned value.
     * @return This builder.
     */
    fun u64(value: ULong): Canonical {
        for (shift in 56 downTo 0 step 8) out.write(((value shr shift) and 0xFFu).toInt())
        return this
    }

    /**
     * Appends a UUID as its 16 bytes in RFC 9562 order, or the nil UUID for `null`.
     *
     * @param value UUID, or `null` when absent.
     * @return This builder.
     */
    fun uuid(value: Uuid?): Canonical {
        out.write((value ?: Uuid.NIL).toByteArray())
        return this
    }

    /**
     * Appends exactly 32 raw bytes, such as a public key, or 32 zero bytes for `null`.
     *
     * @param value 32-byte value, or `null` when absent.
     * @return This builder.
     */
    fun key32(value: ByteString?): Canonical = bytes32(value)

    /**
     * Appends a 32-byte digest computed elsewhere, or 32 zero bytes for `null`.
     *
     * @param value 32-byte digest, or `null` when absent.
     * @return This builder.
     */
    fun digest32(value: ByteString?): Canonical = bytes32(value)

    /**
     * Returns the message.
     *
     * @return Canonical bytes appended so far.
     */
    fun build(): ByteString = ByteString(out.toByteArray())

    /** Appends a 32-byte value or its absence. */
    private fun bytes32(value: ByteString?): Canonical {
        require(value == null || value.size == 32) { "A 32-byte field needs 32 bytes" }
        out.write(value?.toByteArray() ?: ByteArray(32))
        return this
    }
}

/**
 * SHA-256 of [bytes].
 *
 * @param bytes Bytes to digest.
 * @return 32-byte digest.
 */
internal fun sha256(bytes: ByteString): ByteString =
    ByteString(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()))

/**
 * Tells whether a 32-byte field is absent: `null` or all zero bytes (`PROTOCOL.md` §3).
 *
 * @param value Field value.
 * @return Whether it encodes as absent.
 */
internal fun isAbsent(value: ByteString?): Boolean = value == null || (0 until value.size).all { value[it] == 0.toByte() }
