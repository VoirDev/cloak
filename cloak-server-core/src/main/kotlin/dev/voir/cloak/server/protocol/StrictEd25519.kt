package dev.voir.cloak.server.protocol

import kotlinx.io.bytestring.ByteString
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Why a signature is refused (`PROTOCOL.md` §2).
 *
 * @property code Reason as the test vectors name it.
 */
internal enum class SignatureRefusal(
    /** Reason as the test vectors name it. */
    val code: String,
) {
    /** Malformed blob, or the equation does not hold. */
    BAD_SIGNATURE("bad_signature"),

    /** `S` is not below the group order, or `R` is not canonical. */
    NON_CANONICAL_SIGNATURE("non_canonical_signature"),

    /** The public key is not a canonical encoding. */
    NON_CANONICAL_KEY("non_canonical_key"),

    /** The public key is a point of small order. */
    SMALL_ORDER_KEY("small_order_key"),
}

/**
 * Ed25519 verified strictly, as RFC 8032 §5.1.7 says, without ZIP-215 relaxations, so the server
 * refuses exactly the signatures every client refuses (`PROTOCOL.md` §2). The encoding checks run
 * first; the JDK's Ed25519 then checks the equation.
 */
internal object StrictEd25519 {
    /** Order of the edwards25519 prime-order subgroup. */
    private val GROUP_ORDER: BigInteger =
        BigInteger.TWO.pow(252).add(BigInteger("27742317777372353535851937790883648493"))

    /** The edwards25519 field prime. */
    private val FIELD_PRIME: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))

    /** Encodings of the eight small-order points of edwards25519, as lowercase hex. */
    private val SMALL_ORDER_POINTS: Set<String> = setOf(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    )

    /** DER prefix that turns a raw 32-byte Ed25519 key into an X.509 SubjectPublicKeyInfo. */
    private val SPKI_PREFIX = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    /**
     * Checks a signature blob strictly.
     *
     * @param publicKey Signer's raw 32-byte Ed25519 key.
     * @param message Canonical message that was signed.
     * @param signatureBlob `0x01 ‖ signature (64)`.
     * @return `null` when it verifies, otherwise why it is refused.
     */
    fun check(publicKey: ByteString, message: ByteString, signatureBlob: ByteString): SignatureRefusal? {
        if (signatureBlob.size != 65 || signatureBlob[0] != 1.toByte()) return SignatureRefusal.BAD_SIGNATURE
        if (publicKey.size != 32) return SignatureRefusal.NON_CANONICAL_KEY
        val raw = signatureBlob.toByteArray(startIndex = 1)
        if (littleEndian(raw.copyOfRange(32, 64)) >= GROUP_ORDER) return SignatureRefusal.NON_CANONICAL_SIGNATURE
        if (yCoordinate(raw.copyOfRange(0, 32)) >= FIELD_PRIME) return SignatureRefusal.NON_CANONICAL_SIGNATURE
        if (yCoordinate(publicKey.toByteArray()) >= FIELD_PRIME) return SignatureRefusal.NON_CANONICAL_KEY
        if (isSmallOrder(publicKey)) return SignatureRefusal.SMALL_ORDER_KEY
        return try {
            val key = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(SPKI_PREFIX + publicKey.toByteArray()))
            val valid = Signature.getInstance("Ed25519").run {
                initVerify(key)
                update(message.toByteArray())
                verify(raw)
            }
            if (valid) null else SignatureRefusal.BAD_SIGNATURE
        } catch (_: GeneralSecurityException) {
            SignatureRefusal.BAD_SIGNATURE
        }
    }

    /**
     * Tells whether a public key is unusable as anyone's signing key: not 32 bytes, not canonical,
     * or of small order. The server refuses such keys at registration.
     *
     * @param publicKey Raw Ed25519 public key.
     * @return Whether the key must be refused.
     */
    fun isUnusableKey(publicKey: ByteString): Boolean =
        publicKey.size != 32 || yCoordinate(publicKey.toByteArray()) >= FIELD_PRIME || isSmallOrder(publicKey)

    /** Whether a 32-byte key encodes a small-order point. */
    private fun isSmallOrder(publicKey: ByteString): Boolean =
        publicKey.toByteArray().joinToString("") { "%02x".format(it) } in SMALL_ORDER_POINTS

    /** Reads bytes as a little-endian unsigned integer. */
    private fun littleEndian(bytes: ByteArray): BigInteger = BigInteger(1, bytes.reversedArray())

    /** The y coordinate of an encoded point: its little-endian value without the sign bit. */
    private fun yCoordinate(point: ByteArray): BigInteger = littleEndian(point).clearBit(255)
}
