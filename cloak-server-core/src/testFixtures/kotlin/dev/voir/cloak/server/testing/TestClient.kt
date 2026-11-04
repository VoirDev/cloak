package dev.voir.cloak.server.testing

import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.RegisterIdentityCommand
import dev.voir.cloak.server.identity.domain.ReplaceKeysCommand
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.protocol.LogFields
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.protocol.SectionWriteFields
import kotlinx.io.bytestring.ByteString
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import kotlin.uuid.Uuid

/**
 * A client of one user that signs exactly like a real Cloak client. Envelopes, bundles and
 * ciphertext are random blobs of the right shape: the server never opens them.
 *
 * @property hostUserId The user, by the host's id; a random one by default.
 */
public class TestClient(
    public val hostUserId: HostUserId = HostUserId.of("host-${Uuid.random()}"),
) {
    /** The user's Cloak id, derived from [hostUserId]. */
    public val id: UserId = hostUserId.userId

    /** Signing key pair of the current version. */
    private var signing: KeyPair = newKeyPair()

    /** Recovery signing key pair of the current version. */
    private var recovery: KeyPair = newKeyPair()

    /** Key pairs and public keys of the version [replacement] introduced, until [acceptReplacement]. */
    private var pending: Triple<KeyPair, KeyPair, PublicKeys>? = null

    /** The current key version's public keys. */
    public var keys: PublicKeys = publicKeys(1, signing, recovery)
        private set

    /** Registration of key version 1 with its self-signed statement. */
    public fun registration(): RegisterIdentityCommand =
        RegisterIdentityCommand(
            cryptoSuite = 1,
            encryptionPublicKey = keys.encryptionPublicKey,
            signingPublicKey = keys.signingPublicKey,
            recoverySigningPublicKey = keys.recoverySigningPublicKey,
            signature = sign(Messages.keyStatement(keys, null)),
            kdf = kdf(),
            privateKeyBundle = TestBlobs.blob(41 + 129),
            recoveryKeyBundle = TestBlobs.blob(41 + 129),
        )

    /**
     * Prepares the next key version, signed by its new signing key and the current recovery key.
     * Call [acceptReplacement] once the server stored it.
     *
     * @return The command for `replaceKeys`.
     */
    public fun replacement(): ReplaceKeysCommand {
        val next = newKeyPair() to newKeyPair()
        val nextKeys = publicKeys(keys.keyVersion + 1, next.first, next.second)
        pending = Triple(next.first, next.second, nextKeys)
        val message = Messages.keyStatement(nextKeys, Messages.keysDigest(keys))
        return ReplaceKeysCommand(
            expectedKeyVersion = keys.keyVersion,
            encryptionPublicKey = nextKeys.encryptionPublicKey,
            signingPublicKey = nextKeys.signingPublicKey,
            recoverySigningPublicKey = nextKeys.recoverySigningPublicKey,
            signature = sign(next.first, message),
            recoverySignature = sign(recovery, message),
            kdf = kdf(),
            privateKeyBundle = TestBlobs.blob(41 + 129 + 32),
            recoveryKeyBundle = TestBlobs.blob(41 + 129 + 32),
        )
    }

    /** Switches to the key version [replacement] prepared; the old keys stay usable via [signAsOld]. */
    public fun acceptReplacement() {
        val (nextSigning, nextRecovery, nextKeys) = checkNotNull(pending)
        old = signing
        signing = nextSigning
        recovery = nextRecovery
        keys = nextKeys
        pending = null
    }

    /** Signing key pair of the previous version, after a replacement. */
    private var old: KeyPair? = null

    /**
     * Signs a log entry.
     *
     * @param fields The entry; its author must be this user.
     * @return The signature blob.
     */
    internal fun signEntry(fields: LogFields): ByteString = sign(Messages.logEntry(fields))

    /**
     * Signs a section write.
     *
     * @param fields The write; its writer must be this user.
     * @return The signature blob.
     */
    internal fun signWrite(fields: SectionWriteFields): ByteString = sign(Messages.sectionWrite(fields))

    /**
     * Signs with the previous version's signing key, as a thief of replaced keys would.
     *
     * @param message Canonical message.
     * @return The signature blob.
     */
    public fun signAsOld(message: ByteString): ByteString = sign(checkNotNull(old), message)

    /**
     * Signs a canonical message with the current signing key.
     *
     * @param message Canonical message.
     * @return `0x01` followed by the Ed25519 signature.
     */
    public fun sign(message: ByteString): ByteString = sign(signing, message)

    /** Helpers shared by every client. */
    private companion object {
        /** Source of fresh keys. */
        val RANDOM = SecureRandom()

        /** A fresh Ed25519 key pair. */
        fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").apply { initialize(255, RANDOM) }.generateKeyPair()

        /** Raw 32-byte Ed25519 public key: the last 32 bytes of the X.509 encoding. */
        fun raw(pair: KeyPair): ByteString = ByteString(pair.public.encoded.takeLast(32).toByteArray())

        /** KDF parameters of a valid shape. */
        fun kdf(): KdfParams = KdfParams(salt = TestBlobs.random(16), memoryKib = 65_536, iterations = 3, parallelism = 1)

        /** Signs [message] with [pair]. */
        fun sign(pair: KeyPair, message: ByteString): ByteString {
            val signature = Signature.getInstance("Ed25519").run {
                initSign(pair.private)
                update(message.toByteArray())
                sign()
            }
            return ByteString(byteArrayOf(1) + signature)
        }
    }

    /** Public keys of one version; the encryption key is random, since the server never uses it. */
    private fun publicKeys(version: Int, signingPair: KeyPair, recoveryPair: KeyPair): PublicKeys =
        PublicKeys(id, version, 1, TestBlobs.random(32), raw(signingPair), raw(recoveryPair))
}
