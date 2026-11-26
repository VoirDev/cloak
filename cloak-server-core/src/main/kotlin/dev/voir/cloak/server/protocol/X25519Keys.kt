package dev.voir.cloak.server.protocol

import kotlinx.io.bytestring.ByteString
import java.math.BigInteger

/**
 * X25519 public keys as every client checks them before sealing to one (`PROTOCOL.md` §5.1): the
 * server refuses at registration and key replacement any key a vault key could not be sealed to,
 * so one member cannot make every rotation that keeps them fail.
 */
internal object X25519Keys {
    /** The curve25519 field prime. */
    private val FIELD_PRIME: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))

    /** u-coordinates of the five points of small order, little-endian hex: 0, 1, p − 1 and the two of order 8. */
    private val SMALL_ORDER: Set<String> = setOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    )

    /**
     * Why a key is refused, as the test vectors name it.
     *
     * @param publicKey Raw X25519 public key.
     * @return `null` when usable, `non_canonical_key` for a key not 32 bytes, with its top bit set or
     *   not below the field prime, `small_order_key` for a point of small order.
     */
    fun refusal(publicKey: ByteString): SignatureRefusal? {
        val bytes = publicKey.toByteArray()
        if (bytes.size != 32 || bytes[31].toInt() and 0x80 != 0) return SignatureRefusal.NON_CANONICAL_KEY
        if (BigInteger(1, bytes.reversedArray()) >= FIELD_PRIME) return SignatureRefusal.NON_CANONICAL_KEY
        return if (bytes.joinToString("") { "%02x".format(it) } in SMALL_ORDER) SignatureRefusal.SMALL_ORDER_KEY else null
    }
}
