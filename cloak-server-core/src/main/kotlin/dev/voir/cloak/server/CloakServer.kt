package dev.voir.cloak.server

import dev.voir.cloak.server.access.AccessOperations
import dev.voir.cloak.server.identity.IdentityOperations
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.meta.Meta
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.persistence.CloakClock
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.section.NodeOperations
import dev.voir.cloak.server.section.SectionOperations
import dev.voir.cloak.server.vault.MemberOperations
import dev.voir.cloak.server.vault.VaultOperations
import org.jetbrains.exposed.v1.core.DatabaseConfig
import org.jetbrains.exposed.v1.jdbc.Database
import javax.sql.DataSource
import kotlin.time.Clock

/**
 * The framework-free Cloak server: every operation of the API, grouped as the spec groups them.
 *
 * The host's adapter (the Spring Boot starter) authenticates the caller, maps HTTP to these calls and renders
 * [dev.voir.cloak.server.error.CloakException] as problem details. Each call runs in its own
 * transaction on [dataSource] and blocks the calling thread.
 *
 * The host migrates the schema with [dev.voir.cloak.server.persistence.CloakMigrations] before
 * the first call.
 *
 * Exposed never retries a Cloak transaction: a statement that failed, ran out of time or lost a
 * deadlock answers at once, so [CloakSettings] bound the time a request holds the database.
 *
 * @param dataSource The host's PostgreSQL database.
 * @param clock Source of time; inject a fixed clock in tests.
 * @param settings Request size limit, database timeouts and the event listener.
 */
public class CloakServer @JvmOverloads constructor(
    dataSource: DataSource,
    clock: Clock = Clock.System,
    settings: CloakSettings = CloakSettings.defaults(),
) {
    /** Shared database handle, clock and settings. */
    private val context = CloakContext(
        Database.connect(dataSource, databaseConfig = DatabaseConfig { defaultMaxAttempts = 1 }),
        CloakClock(clock),
        settings,
    )

    /** The caller's identity and other users' key versions. */
    public val identity: IdentityOperations = IdentityOperations(context)

    /** Vaults, their keys, logs and checkpoints. */
    public val vaults: VaultOperations = VaultOperations(context)

    /** Members, envelopes, leaving, rotation and key replacements. */
    public val members: MemberOperations = MemberOperations(context)

    /** Sections, per vault and in batches. */
    public val sections: SectionOperations = SectionOperations(context)

    /** Nodes: all readable sections of a node, across vaults. */
    public val nodes: NodeOperations = NodeOperations(context)

    /** Access checks for the host's own endpoints. */
    public val access: AccessOperations = AccessOperations(context)

    /**
     * Returns protocol capabilities and limits; needs no authentication.
     *
     * @return This server's capabilities.
     */
    public fun meta(): Meta =
        Meta(
            apiVersion = API_VERSION,
            protocolVersion = PROTOCOL_VERSION,
            cryptoSuites = listOf(IdentityOperations.CRYPTO_SUITE),
            acceptedBlobFormats = BlobRules.acceptedFormats,
            deprecatedBlobFormats = BlobRules.deprecatedFormats,
            limits = Limits(
                maxSectionBytes = BlobRules.MAX_CIPHERTEXT_BYTES,
                maxRequestBytes = context.settings.maxRequestBytes,
                maxBatchSize = Limits.MAX_BATCH_SIZE,
                maxPageSize = PageRequest.MAX_LIMIT,
                maxIndexPageSize = PageRequest.MAX_INDEX_LIMIT,
                maxMembersPerVault = Limits.MAX_MEMBERS_PER_VAULT,
                maxSectionsPerVault = Limits.MAX_SECTIONS_PER_VAULT,
                maxStoredSectionsPerVault = context.settings.maxStoredSectionsPerVault,
                writePauseSeconds = context.settings.writePause.seconds.toInt(),
                writePauseIntervalSeconds = context.settings.writePauseInterval.seconds.toInt(),
                minKdfMemoryKib = Limits.MIN_KDF_MEMORY_KIB,
                maxKdfMemoryKib = Limits.MAX_KDF_MEMORY_KIB,
                minKdfIterations = Limits.MIN_KDF_ITERATIONS,
                maxKdfIterations = Limits.MAX_KDF_ITERATIONS,
                maxPendingInvitations = context.settings.maxPendingInvitations,
                maxPendingInvitationsPerInviter = context.settings.maxPendingInvitationsPerInviter,
            ),
        )

    /** Versions this server implements. */
    private companion object {
        /** Version of `cloak-api.v1.yaml`. */
        const val API_VERSION = "1.0.0"

        /** Version of `PROTOCOL.md`. */
        const val PROTOCOL_VERSION = 1
    }
}
