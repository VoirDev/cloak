package dev.voir.cloak.server.identity.domain

import kotlinx.io.bytestring.ByteString

/**
 * Argon2id parameters a client uses to derive the master key from the password
 * (`PROTOCOL.md` §5.3).
 *
 * @property salt 16 random bytes.
 * @property memoryKib Memory cost in KiB; 65 536 to 1 048 576.
 * @property iterations Iteration count; 2 to 10.
 * @property parallelism Lanes; always 1 in crypto suite 1.
 */
public data class KdfParams(
    /** 16 random bytes. */
    public val salt: ByteString,
    /** Memory cost in KiB. */
    public val memoryKib: Int,
    /** Iteration count. */
    public val iterations: Int,
    /** Lanes; always 1. */
    public val parallelism: Int = 1,
)
