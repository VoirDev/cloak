package dev.voir.cloak.server.protocol

import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import kotlinx.io.bytestring.ByteString

/**
 * Checkpoints as RFC 6962 Merkle trees over the latest write of every section of a vault
 * (`PROTOCOL.md` §7.5).
 */
internal object Merkle {
    /** Orders sections by node id bytes, then section name bytes: the order of a checkpoint's leaves. */
    val sectionOrder: Comparator<CheckpointLeaf> = Comparator { a, b ->
        compareBytes(a.nodeId.value.toByteArray(), b.nodeId.value.toByteArray()).takeIf { it != 0 }
            ?: compareBytes(a.sectionName.value.encodeToByteArray(), b.sectionName.value.encodeToByteArray())
    }

    /**
     * Encodes a leaf's data: `uuid nodeId ‖ str sectionName ‖ u64 dataVersion ‖ digest32 writeHash`.
     *
     * @param leaf The leaf.
     * @return Leaf data, before hashing.
     */
    fun leafData(leaf: CheckpointLeaf): ByteString =
        Canonical()
            .uuid(leaf.nodeId.value)
            .str(leaf.sectionName.value)
            .u64(leaf.dataVersion)
            .digest32(leaf.writeHash)
            .build()

    /**
     * Hashes a leaf: `SHA-256(0x00 ‖ leafData)`.
     *
     * @param leaf The leaf.
     * @return 32-byte leaf hash.
     */
    fun leafHash(leaf: CheckpointLeaf): ByteString = sha256(ByteString(byteArrayOf(0) + leafData(leaf).toByteArray()))

    /**
     * Computes a checkpoint over leaves already in [sectionOrder].
     *
     * @param sortedLeaves Leaves in checkpoint order.
     * @return The root; SHA-256 of nothing when there are none.
     */
    fun root(sortedLeaves: List<CheckpointLeaf>): ByteString = MerkleTree(sortedLeaves.map(::leafHash)).root

    /**
     * Checks an audit path as RFC 9162 §2.1.3.2 says.
     *
     * @param index Index of the leaf.
     * @param size Number of leaves.
     * @param hash Hash of the leaf.
     * @param path Sibling hashes from the leaf up.
     * @param root Root the path must reach.
     * @return Whether the leaf is at [index] in the tree with [root].
     */
    fun verifyInclusion(index: Long, size: Long, hash: ByteString, path: List<ByteString>, root: ByteString): Boolean {
        if (index < 0 || index >= size) return false
        var fn = index
        var sn = size - 1
        var result = hash
        for (sibling in path) {
            if (sn == 0L) return false
            if (fn and 1L == 1L || fn == sn) {
                result = nodeHash(sibling, result)
                if (fn and 1L == 0L) {
                    do {
                        fn = fn shr 1
                        sn = sn shr 1
                    } while (fn and 1L == 0L && fn != 0L)
                }
            } else {
                result = nodeHash(result, sibling)
            }
            fn = fn shr 1
            sn = sn shr 1
        }
        return sn == 0L && result == root
    }

    /** Hashes an inner node: `SHA-256(0x01 ‖ left ‖ right)`. */
    internal fun nodeHash(left: ByteString, right: ByteString): ByteString =
        sha256(ByteString(byteArrayOf(1) + left.toByteArray() + right.toByteArray()))

    /** Compares byte arrays lexicographically as unsigned bytes. */
    private fun compareBytes(a: ByteArray, b: ByteArray): Int = java.util.Arrays.compareUnsigned(a, b)
}

/**
 * An RFC 6962 Merkle tree built once over a checkpoint's leaf hashes, so that every audit path
 * costs O(log n) instead of rebuilding the tree.
 *
 * Level 0 holds the leaf hashes; each next level hashes adjacent pairs, and a lone last node is
 * carried up unchanged. That is the same tree as RFC 6962 §2.1, whose split at the largest power
 * of two below n puts every incomplete subtree at the right edge.
 *
 * @param leafHashes Leaf hashes in checkpoint order.
 */
internal class MerkleTree(leafHashes: List<ByteString>) {
    /** Hashes by level, leaves first; the last level holds the root, if any leaf. */
    private val levels: List<List<ByteString>> = buildList {
        var level = leafHashes.toList()
        add(level)
        while (level.size > 1) {
            level = List((level.size + 1) / 2) { i ->
                if (2 * i + 1 < level.size) Merkle.nodeHash(level[2 * i], level[2 * i + 1]) else level[2 * i]
            }
            add(level)
        }
    }

    /** Number of leaves. */
    val size: Int get() = levels.first().size

    /** The root; SHA-256 of nothing when there are no leaves. */
    val root: ByteString = levels.last().singleOrNull() ?: sha256(ByteString())

    /**
     * RFC 6962 §2.1.1 audit path of one leaf.
     *
     * @param index Index of the leaf, from 0.
     * @return Sibling hashes from the leaf up to the root.
     */
    fun auditPath(index: Int): List<ByteString> {
        require(index in 0 until size) { "No leaf at $index of $size." }
        val path = ArrayList<ByteString>()
        var position = index
        for (level in levels.dropLast(1)) {
            val sibling = position xor 1
            if (sibling < level.size) path += level[sibling]
            position /= 2
        }
        return path
    }
}
