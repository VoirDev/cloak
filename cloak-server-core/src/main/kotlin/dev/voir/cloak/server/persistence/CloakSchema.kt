package dev.voir.cloak.server.persistence

import dev.voir.cloak.server.identity.persistence.IdentitiesTable
import dev.voir.cloak.server.identity.persistence.IdentityKeysTable
import dev.voir.cloak.server.section.persistence.SectionRemovalsTable
import dev.voir.cloak.server.section.persistence.SectionsTable
import dev.voir.cloak.server.vault.persistence.AcceptedInvitersTable
import dev.voir.cloak.server.vault.persistence.CheckpointLeavesTable
import dev.voir.cloak.server.vault.persistence.NodeShareNamesTable
import dev.voir.cloak.server.vault.persistence.NodeSharesTable
import dev.voir.cloak.server.vault.persistence.NodesTable
import dev.voir.cloak.server.vault.persistence.VaultKeysTable
import dev.voir.cloak.server.vault.persistence.VaultLogTable
import dev.voir.cloak.server.vault.persistence.VaultMembersTable
import dev.voir.cloak.server.vault.persistence.VaultsTable
import dev.voir.cloak.server.vault.persistence.WritePauseRequestsTable
import org.jetbrains.exposed.v1.core.Table

/**
 * The `cloak` database schema, which Cloak owns and migrates with its own Flyway history.
 *
 * The host process runs this history at startup, separately from its own migrations.
 */
internal object CloakSchema {
    /** PostgreSQL schema that holds every Cloak table and the Flyway history. */
    const val NAME: String = "cloak"

    /** Flyway location of the Cloak migrations. */
    const val MIGRATION_LOCATION: String = "classpath:db/migration/cloak"

    /**
     * Version of the latest migration this build carries; a test checks it against the migration
     * files, and the health check against the database.
     */
    const val LATEST_VERSION: String = "1"

    /** Flyway history table, created inside [NAME]. */
    const val HISTORY_TABLE: String = "flyway_schema_history"

    /** Every Cloak table, in dependency order; used by the schema drift test. */
    val tables: List<Table> = listOf(
        IdentitiesTable,
        IdentityKeysTable,
        VaultsTable,
        VaultKeysTable,
        VaultMembersTable,
        VaultLogTable,
        CheckpointLeavesTable,
        SectionsTable,
        WritePauseRequestsTable,
        SectionRemovalsTable,
        NodesTable,
        NodeSharesTable,
        NodeShareNamesTable,
        AcceptedInvitersTable,
    )
}
