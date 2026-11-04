package dev.voir.cloak.server.testing

import kotlinx.io.bytestring.ByteString
import java.security.SecureRandom

/** Random values of the shapes the API accepts. */
public object TestBlobs {
    /** Source of random bytes. */
    private val RANDOM = SecureRandom()

    /**
     * Random bytes.
     *
     * @param size Number of bytes.
     * @return Fresh random bytes.
     */
    public fun random(size: Int): ByteString = ByteString(ByteArray(size).also(RANDOM::nextBytes))

    /**
     * A blob of format 1: `0x01` followed by random bytes.
     *
     * @param size Total size.
     * @return The blob.
     */
    public fun blob(size: Int): ByteString = ByteString(byteArrayOf(1) + ByteArray(size - 1).also(RANDOM::nextBytes))

    /** A vault key sealed to a member: 81 bytes. */
    public fun envelope(): ByteString = blob(81)

    /** A previous vault key wrapped by the next one: 73 bytes. */
    public fun wrappedKey(): ByteString = blob(73)

    /**
     * Section ciphertext of whole padded blocks.
     *
     * @param blocks Number of 256-byte blocks.
     * @return The ciphertext.
     */
    public fun ciphertext(blocks: Int = 1): ByteString = blob(41 + 256 * blocks)
}
