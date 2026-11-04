package dev.voir.cloak.server.paging

import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.persistence.LeafPosition
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import kotlin.io.encoding.Base64
import kotlin.uuid.Uuid

/**
 * Keyset cursor of a checkpoint's leaf list: the checkpoint and the last section of the previous
 * page, in checkpoint order. It names its checkpoint, so it cannot continue another one.
 *
 * Encoded as base64url without padding of `0x03 ‖ u64 seq ‖ uuid nodeId ‖ UTF-8 sectionName`.
 */
internal object LeafCursor {
    /** Byte that tags a leaf cursor; [KeysetCursor.Kind] uses the others. */
    private const val KIND: Byte = 3

    /** Base64url without padding, as every binary value of the API. */
    private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

    /** Pointer reported for a bad cursor. */
    private const val POINTER = "#/query/cursor"

    /**
     * Encodes the position after a page.
     *
     * @param seq Entry carrying the checkpoint.
     * @param after The last section of the page.
     * @return Opaque cursor for `nextCursor`.
     */
    fun encode(seq: Long, after: LeafPosition): String {
        val name = after.sectionName.value.encodeToByteArray()
        val buffer = ByteBuffer.allocate(1 + 8 + 16 + name.size)
            .put(KIND)
            .putLong(seq)
            .put(after.nodeId.value.toByteArray())
            .put(name)
        return BASE64.encode(buffer.array())
    }

    /**
     * Decodes a cursor of the checkpoint of [seq], or returns `null` for the first page.
     *
     * @param cursor Value from the request, or `null`.
     * @param seq Entry carrying the checkpoint being read.
     * @return The position to continue after, or `null` when [cursor] is `null`.
     * @throws CloakException `validation_failed` when the cursor is malformed or of another listing.
     */
    fun decode(cursor: String?, seq: Long): LeafPosition? {
        if (cursor == null) return null
        val invalid = CloakException.invalid(POINTER, "format", "Not a cursor of this listing.")
        val buffer = try {
            ByteBuffer.wrap(BASE64.decode(cursor))
        } catch (_: IllegalArgumentException) {
            throw invalid
        }
        return try {
            if (buffer.get() != KIND || buffer.getLong() != seq) throw invalid
            val nodeId = Uuid.fromByteArray(ByteArray(Uuid.SIZE_BYTES).also(buffer::get))
            val name = ByteArray(buffer.remaining()).also(buffer::get).decodeToString()
            if (!SectionName.PATTERN.matches(name)) throw invalid
            LeafPosition(NodeId(nodeId), SectionName(name))
        } catch (_: BufferUnderflowException) {
            throw invalid
        }
    }
}
