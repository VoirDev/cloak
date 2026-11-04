package dev.voir.cloak.server.paging

import dev.voir.cloak.server.error.CloakException
import java.nio.ByteBuffer
import java.nio.BufferUnderflowException
import kotlin.io.encoding.Base64
import kotlin.time.Instant
import kotlin.uuid.Uuid

/**
 * Position after the last item of a page: the sort key of that item.
 *
 * Cursor listings sort by `(createdAt, id)`, so the key holds an instant and a UUID; the vault
 * log and a vault's sections page by their own sequence numbers instead. The [kind]
 * byte stops a cursor of one listing from being replayed against another.
 *
 * @property kind Listing the cursor belongs to.
 * @property createdAt Sort instant of the last item, at microsecond precision.
 * @property id UUID tie-breaker of the last item.
 */
internal data class KeysetCursor(
    val kind: Kind,
    val createdAt: Instant,
    val id: Uuid,
) {
    /**
     * Encodes the cursor as base64url without padding.
     *
     * @return Opaque cursor for `nextCursor`.
     */
    fun encode(): String {
        val buffer = ByteBuffer.allocate(1 + 8 + 16)
            .put(kind.code)
            .putLong(createdAt.epochMicros())
            .put(id.toByteArray())
        return BASE64.encode(buffer.array())
    }

    /**
     * Listings that issue cursors.
     *
     * @property code Byte that tags the cursor.
     */
    enum class Kind(
        /** Byte that tags the cursor. */
        val code: Byte,
    ) {
        /** `GET /vaults`. */
        VAULTS(2),
    }

    /** Decoding of cursors received from clients. */
    companion object {
        /** Base64url without padding, as every binary value of the API. */
        private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        /** Pointer reported for a bad cursor. */
        private const val POINTER = "#/query/cursor"

        /**
         * Decodes a cursor of [kind], or returns `null` for the first page.
         *
         * @param cursor Value from the request, or `null`.
         * @param kind Listing being read.
         * @return The position, or `null` when [cursor] is `null`.
         * @throws CloakException `validation_failed` when the cursor is malformed or from another listing.
         */
        fun decode(cursor: String?, kind: Kind): KeysetCursor? {
            if (cursor == null) return null
            val invalid = CloakException.invalid(POINTER, "format", "Not a cursor of this listing.")
            val buffer = try {
                ByteBuffer.wrap(BASE64.decode(cursor))
            } catch (_: IllegalArgumentException) {
                throw invalid
            }
            return try {
                if (buffer.get() != kind.code) throw invalid
                val micros = buffer.getLong()
                // Instants PostgreSQL stores: years 1 to 9999.
                if (micros !in MIN_MICROS..MAX_MICROS) throw invalid
                val id = ByteArray(16).also(buffer::get)
                if (buffer.hasRemaining()) throw invalid
                KeysetCursor(
                    kind = kind,
                    createdAt = Instant.fromEpochSeconds(
                        Math.floorDiv(micros, MICROS_PER_SECOND),
                        Math.floorMod(micros, MICROS_PER_SECOND) * NANOS_PER_MICRO,
                    ),
                    id = Uuid.fromByteArray(id),
                )
            } catch (_: BufferUnderflowException) {
                throw invalid
            }
        }

        /**
         * Validates a page size.
         *
         * @param limit Requested size.
         * @param max Largest size of the listing.
         * @return The same size.
         * @throws CloakException `validation_failed` outside 1 to [max].
         */
        fun checkLimit(limit: Int, max: Int = PageRequest.MAX_LIMIT): Int {
            if (limit !in 1..max) {
                throw CloakException.invalid("#/query/limit", "range", "Must be 1 to $max.")
            }
            return limit
        }

        /** 0001-01-01T00:00:00Z in microseconds since the epoch. */
        private const val MIN_MICROS = -62_135_596_800_000_000L

        /** 9999-12-31T23:59:59.999999Z in microseconds since the epoch. */
        private const val MAX_MICROS = 253_402_300_799_999_999L

        /** Microseconds in a second. */
        private const val MICROS_PER_SECOND = 1_000_000L

        /** Nanoseconds in a microsecond. */
        private const val NANOS_PER_MICRO = 1_000L

        /** Microseconds since the epoch; instants are stored at microsecond precision. */
        private fun Instant.epochMicros(): Long =
            epochSeconds * MICROS_PER_SECOND + nanosecondsOfSecond / NANOS_PER_MICRO
    }
}
