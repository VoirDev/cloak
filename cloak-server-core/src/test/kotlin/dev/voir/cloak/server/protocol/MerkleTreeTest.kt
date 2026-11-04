package dev.voir.cloak.server.protocol

import kotlinx.io.bytestring.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Checks [MerkleTree] against the recursive definitions of RFC 6962 §2.1. */
class MerkleTreeTest {
    @Test
    fun `root and every audit path match RFC 6962 for sizes 0 to 300`() {
        for (size in 0..300) {
            val hashes = List(size) { sha256(ByteString(byteArrayOf(0) + "leaf $it".encodeToByteArray())) }
            val tree = MerkleTree(hashes)

            assertEquals(referenceRoot(hashes), tree.root, "root of $size")
            assertEquals(size, tree.size)
            for (index in hashes.indices) {
                val path = tree.auditPath(index)
                assertEquals(referencePath(index, hashes), path, "path of $index in $size")
                assertTrue(Merkle.verifyInclusion(index.toLong(), size.toLong(), hashes[index], path, tree.root))
            }
        }
    }

    @Test
    fun `a path does not prove another leaf, another position or a smaller tree`() {
        val hashes = List(37) { sha256(ByteString(byteArrayOf(it.toByte()))) }
        val tree = MerkleTree(hashes)
        val path = tree.auditPath(5)

        assertFalse(Merkle.verifyInclusion(5, 37, hashes[6], path, tree.root))
        assertFalse(Merkle.verifyInclusion(6, 37, hashes[5], path, tree.root))
        assertFalse(Merkle.verifyInclusion(5, 32, hashes[5], path, tree.root))
    }

    @Test
    fun `an index outside the tree is refused`() {
        val tree = MerkleTree(List(3) { sha256(ByteString(byteArrayOf(it.toByte()))) })

        assertFailsWith<IllegalArgumentException> { tree.auditPath(3) }
        assertFailsWith<IllegalArgumentException> { MerkleTree(emptyList()).auditPath(0) }
    }

    /** RFC 6962 §2.1 MTH, recursively. */
    private fun referenceRoot(hashes: List<ByteString>): ByteString =
        when (hashes.size) {
            0 -> sha256(ByteString())
            1 -> hashes.single()
            else -> {
                val split = split(hashes.size)
                Merkle.nodeHash(referenceRoot(hashes.subList(0, split)), referenceRoot(hashes.subList(split, hashes.size)))
            }
        }

    /** RFC 6962 §2.1.1 PATH, recursively. */
    private fun referencePath(index: Int, hashes: List<ByteString>): List<ByteString> {
        if (hashes.size <= 1) return emptyList()
        val split = split(hashes.size)
        return if (index < split) {
            referencePath(index, hashes.subList(0, split)) + referenceRoot(hashes.subList(split, hashes.size))
        } else {
            referencePath(index - split, hashes.subList(split, hashes.size)) + referenceRoot(hashes.subList(0, split))
        }
    }

    /** Largest power of two below [n]. */
    private fun split(n: Int): Int {
        var k = 1
        while (k * 2 < n) k *= 2
        return k
    }
}
