package dev.voir.cloak.server.paging

import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.vault.domain.VaultId
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import kotlin.io.encoding.Base64
import kotlin.uuid.Uuid

/**
 * Keyset cursor of a node read: the node and the last section of the previous page, which a node
 * read orders by vault and then section name. It names its node, so it cannot continue another.
 *
 * Encoded as base64url without padding of `0x04 ‖ uuid nodeId ‖ uuid vaultId ‖ UTF-8 sectionName`.
 */
internal object NodeCursor {
    /** Byte that tags a node cursor; [KeysetCursor.Kind] and [LeafCursor] use the others. */
    private const val KIND: Byte = 4

    /** Base64url without padding, as every binary value of the API. */
    private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

    /** Pointer reported for a bad cursor. */
    private const val POINTER = "#/query/cursor"

    /**
     * Encodes the position after a page.
     *
     * @param after The last section of the page.
     * @return Opaque cursor for `nextCursor`.
     */
    fun encode(after: SectionRef): String {
        val name = after.sectionName.value.encodeToByteArray()
        val buffer = ByteBuffer.allocate(1 + 2 * Uuid.SIZE_BYTES + name.size)
            .put(KIND)
            .put(after.nodeId.value.toByteArray())
            .put(after.vaultId.value.toByteArray())
            .put(name)
        return BASE64.encode(buffer.array())
    }

    /**
     * Decodes a cursor of [nodeId], or returns `null` for the first page.
     *
     * @param cursor Value from the request, or `null`.
     * @param nodeId The node being read.
     * @return The section to continue after, or `null` when [cursor] is `null`.
     * @throws CloakException `validation_failed` when the cursor is malformed or of another listing or node.
     */
    fun decode(cursor: String?, nodeId: NodeId): SectionRef? {
        if (cursor == null) return null
        val invalid = CloakException.invalid(POINTER, "format", "Not a cursor of this listing.")
        val buffer = try {
            ByteBuffer.wrap(BASE64.decode(cursor))
        } catch (_: IllegalArgumentException) {
            throw invalid
        }
        return try {
            if (buffer.get() != KIND) throw invalid
            val node = Uuid.fromByteArray(ByteArray(Uuid.SIZE_BYTES).also(buffer::get))
            val vault = Uuid.fromByteArray(ByteArray(Uuid.SIZE_BYTES).also(buffer::get))
            val name = ByteArray(buffer.remaining()).also(buffer::get).decodeToString()
            if (node != nodeId.value || !SectionName.PATTERN.matches(name)) throw invalid
            SectionRef(VaultId(vault), nodeId, SectionName(name))
        } catch (_: BufferUnderflowException) {
            throw invalid
        }
    }
}
