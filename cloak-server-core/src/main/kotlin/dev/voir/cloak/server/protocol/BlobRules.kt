package dev.voir.cloak.server.protocol

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import kotlinx.io.bytestring.ByteString

/**
 * Size and format-version rules for every binary value a client sends (`PROTOCOL.md` §4, §13).
 *
 * The server never parses a blob beyond its first byte; these checks only stop malformed or
 * mis-sized values from being stored.
 */
internal object BlobRules {
    /** The only blob format version today. */
    const val FORMAT_1: Int = 1

    /** Format versions accepted on write. */
    val acceptedFormats: List<Int> = listOf(FORMAT_1)

    /** Format versions still readable but refused on write. */
    val deprecatedFormats: List<Int> = emptyList()

    /** Overhead of an encrypted blob: version, 24-byte nonce and 16-byte tag. */
    const val ENCRYPTED_OVERHEAD: Int = 41

    /** Padding block of section content. */
    const val PADDING_BLOCK: Int = 256

    /** Smallest section ciphertext: one padded block. */
    const val MIN_CIPHERTEXT_BYTES: Int = ENCRYPTED_OVERHEAD + PADDING_BLOCK

    /** Largest section ciphertext. */
    const val MAX_CIPHERTEXT_BYTES: Int = 1_048_576

    /** Largest identity bundle. */
    const val MAX_BUNDLE_BYTES: Int = 49_152

    /** Smallest bundle: an encrypted blob of a bundle plaintext without earlier keys. */
    const val MIN_BUNDLE_BYTES: Int = ENCRYPTED_OVERHEAD + 129

    /** Signature blob: version and a 64-byte Ed25519 signature. */
    const val SIGNATURE_BYTES: Int = 65

    /** Vault key sealed to a member with HPKE: version, 32-byte `enc`, 32-byte key, tag. */
    const val ENVELOPE_BYTES: Int = 81

    /** Previous vault key wrapped by the next one: version, nonce, key, tag. */
    const val WRAPPED_KEY_BYTES: Int = 73

    /** Raw public key, commitment, checkpoint and digest size. */
    const val KEY_BYTES: Int = 32

    /** Argon2id salt size. */
    const val SALT_BYTES: Int = 16

    /**
     * Checks a signature blob.
     *
     * @param value Blob to check.
     * @param pointer JSON Pointer of the value, for the error.
     */
    fun signature(value: ByteString, pointer: String) {
        exactBlob(value, SIGNATURE_BYTES, pointer)
    }

    /**
     * Checks a vault key sealed to a member.
     *
     * @param value Blob to check.
     * @param pointer JSON Pointer of the value, for the error.
     */
    fun envelope(value: ByteString, pointer: String) {
        exactBlob(value, ENVELOPE_BYTES, pointer)
    }

    /**
     * Checks a previous vault key wrapped by the next one.
     *
     * @param value Blob to check.
     * @param pointer JSON Pointer of the value, for the error.
     */
    fun wrappedKey(value: ByteString, pointer: String) {
        exactBlob(value, WRAPPED_KEY_BYTES, pointer)
    }

    /**
     * Checks an identity bundle: an encrypted bundle plaintext of 129 + 32·p bytes, at most 48 KiB.
     *
     * @param value Blob to check.
     * @param pointer JSON Pointer of the value, for the error.
     */
    fun bundle(value: ByteString, pointer: String) {
        format(value, pointer)
        if (value.size < MIN_BUNDLE_BYTES || value.size > MAX_BUNDLE_BYTES || (value.size - MIN_BUNDLE_BYTES) % KEY_BYTES != 0) {
            throw CloakException.invalid(
                pointer,
                "size",
                "Must be an encrypted key bundle of $MIN_BUNDLE_BYTES + 32·p bytes, at most $MAX_BUNDLE_BYTES.",
            )
        }
    }

    /**
     * Checks section ciphertext: an encrypted blob of whole 256-byte padded blocks, at most 1 MiB.
     *
     * @param value Blob to check.
     * @param pointer JSON Pointer of the value, for the error.
     * @throws CloakException `payload_too_large` above 1 MiB, `validation_failed` when not padded.
     */
    fun ciphertext(value: ByteString, pointer: String) {
        if (value.size > MAX_CIPHERTEXT_BYTES) {
            throw CloakException(
                CloakErrorCode.PAYLOAD_TOO_LARGE,
                "Section ciphertext is larger than $MAX_CIPHERTEXT_BYTES bytes.",
            )
        }
        format(value, pointer)
        val paddedSize = value.size - ENCRYPTED_OVERHEAD
        if (value.size < MIN_CIPHERTEXT_BYTES || paddedSize % PADDING_BLOCK != 0) {
            throw CloakException.invalid(pointer, "size", "Must hold content padded to $PADDING_BLOCK-byte blocks.")
        }
    }

    /**
     * Checks a raw value of exactly [size] bytes without a format byte, such as a public key.
     *
     * @param value Value to check.
     * @param size Required size.
     * @param pointer JSON Pointer of the value, for the error.
     */
    fun raw(value: ByteString, size: Int, pointer: String) {
        if (value.size != size) throw CloakException.invalid(pointer, "size", "Must be exactly $size bytes.")
    }

    /**
     * Checks an optional 32-byte value, such as a commitment or checkpoint.
     *
     * @param value Value, or `null`.
     * @param pointer JSON Pointer of the value, for the error.
     */
    fun optionalKey(value: ByteString?, pointer: String) {
        if (value != null) raw(value, KEY_BYTES, pointer)
    }

    /** Checks the size, then the format byte, of a fixed-size blob. */
    private fun exactBlob(value: ByteString, size: Int, pointer: String) {
        format(value, pointer)
        raw(value, size, pointer)
    }

    /** Checks that the first byte is a writable format version. */
    private fun format(value: ByteString, pointer: String) {
        if (value.size == 0) throw CloakException.invalid(pointer, "size", "Must not be empty.")
        val version = value[0].toInt() and 0xFF
        when (version) {
            in acceptedFormats -> Unit
            in deprecatedFormats -> throw CloakException(
                CloakErrorCode.DEPRECATED_FORMAT,
                "Blob format $version at $pointer is read-only; upgrade the client.",
            )
            else -> throw CloakException(
                CloakErrorCode.UNSUPPORTED_FORMAT,
                "Blob format $version at $pointer is not supported.",
            )
        }
    }
}
