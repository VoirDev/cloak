package dev.voir.cloak.server.vault.persistence

import dev.voir.cloak.server.persistence.toByteString
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultKey
import kotlinx.io.bytestring.ByteString
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import kotlin.time.Instant

/** Reads and writes `cloak.vault_keys`. Every function runs inside the caller's transaction. */
internal object VaultKeyRepository {
    /**
     * Stores a key version.
     *
     * @param vaultId Vault.
     * @param version Key version.
     * @param keyCommitment Its commitment from the signed log.
     * @param previousWrappedKey The previous key wrapped by it; `null` for version 1.
     * @param now Creation instant.
     */
    fun insert(vaultId: VaultId, version: Int, keyCommitment: ByteString, previousWrappedKey: ByteString?, now: Instant) {
        VaultKeysTable.insert {
            it[VaultKeysTable.vaultId] = vaultId.value
            it[VaultKeysTable.version] = version
            it[VaultKeysTable.keyCommitment] = keyCommitment.toByteArray()
            it[VaultKeysTable.previousWrappedKey] = previousWrappedKey?.toByteArray()
            it[createdAt] = now
        }
    }

    /**
     * Lists key versions after one, oldest first.
     *
     * @param vaultId Vault.
     * @param afterVersion Versions after this one; 0 for all.
     * @param limit Most versions to return.
     * @return Key versions.
     */
    fun page(vaultId: VaultId, afterVersion: Int, limit: Int): List<VaultKey> =
        VaultKeysTable.selectAll()
            .where { (VaultKeysTable.vaultId eq vaultId.value) and (VaultKeysTable.version greater afterVersion) }
            .orderBy(VaultKeysTable.version to SortOrder.ASC)
            .limit(limit)
            .map {
                VaultKey(
                    version = it[VaultKeysTable.version],
                    previousWrappedKey = it[VaultKeysTable.previousWrappedKey]?.toByteString(),
                    createdAt = it[VaultKeysTable.createdAt],
                )
            }
}
