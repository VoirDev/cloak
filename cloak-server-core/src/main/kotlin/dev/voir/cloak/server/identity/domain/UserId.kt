package dev.voir.cloak.server.identity.domain

import java.security.MessageDigest
import kotlin.uuid.Uuid

/**
 * Cloak's id of a user: `UUIDv5(715ec4b7-23ef-5724-a2a7-6bd5871ab13d, hostUserId)`, derived from
 * the host application's own id (`PROTOCOL.md` §5.0). Every signed message names users by it.
 *
 * Cloak never creates users; it only attaches an identity to a user the host authenticated.
 */
@JvmInline
public value class UserId(
    /** The lowercase RFC 9562 UUID. */
    public val value: Uuid,
) {
    /** Derivation from host ids. */
    public companion object {
        /** Namespace of Cloak user ids: `UUIDv5(NameSpace_URL, "urn:cloak:v1:user")`. */
        public val NAMESPACE: Uuid = Uuid.parse("715ec4b7-23ef-5724-a2a7-6bd5871ab13d")

        /**
         * Derives a user's id from their host user id (RFC 9562 §5.5).
         *
         * @param hostUserId The host's id of the user.
         * @return `UUIDv5(NAMESPACE, UTF-8 bytes of hostUserId)`.
         */
        public fun of(hostUserId: HostUserId): UserId = UserId(uuidV5(NAMESPACE, hostUserId.utf8))

        /** RFC 9562 §5.5 UUIDv5 of [name] under [namespace]. */
        internal fun uuidV5(namespace: Uuid, name: ByteArray): Uuid {
            val sha1 = MessageDigest.getInstance("SHA-1")
            sha1.update(namespace.toByteArray())
            val bytes = sha1.digest(name).copyOf(Uuid.SIZE_BYTES)
            bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x50).toByte()
            bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte()
            return Uuid.fromByteArray(bytes)
        }
    }
}
