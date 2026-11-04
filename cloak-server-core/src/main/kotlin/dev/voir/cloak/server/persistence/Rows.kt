package dev.voir.cloak.server.persistence

import kotlinx.io.bytestring.ByteString

/**
 * Wraps a `bytea` value read from the database without copying it again.
 *
 * @return The bytes as an immutable [ByteString].
 */
internal fun ByteArray.toByteString(): ByteString = ByteString(this)
