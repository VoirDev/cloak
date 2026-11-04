package dev.voir.cloak.server.persistence

import org.flywaydb.core.Flyway
import javax.sql.DataSource

/**
 * Migrates the `cloak` schema with its own Flyway history.
 *
 * The host process calls [migrate] once at startup, before it serves any Cloak request and
 * separately from its own migrations. A failed migration throws, which should fail startup.
 */
public object CloakMigrations {
    /**
     * Applies every pending Cloak migration to [dataSource].
     *
     * Creates the `cloak` schema and its `flyway_schema_history` table when they are missing.
     * Safe to call from several instances at once: Flyway serializes them with a database lock.
     *
     * @param dataSource Connection to the host's PostgreSQL database.
     * @return Number of migrations applied by this call.
     */
    @JvmStatic
    public fun migrate(dataSource: DataSource): Int =
        Flyway.configure()
            .dataSource(dataSource)
            .schemas(CloakSchema.NAME)
            .table(CloakSchema.HISTORY_TABLE)
            .locations(CloakSchema.MIGRATION_LOCATION)
            .load()
            .migrate()
            .migrationsExecuted

    /**
     * Tells whether the `cloak` schema of [dataSource] is reachable and at the version this build
     * expects: its latest successful migration is the latest one the build carries. For a health
     * check; it never migrates and reports no detail.
     *
     * @param dataSource Connection to the host's PostgreSQL database.
     * @return Whether the schema is reachable and current.
     */
    @JvmStatic
    public fun isSchemaCurrent(dataSource: DataSource): Boolean =
        try {
            dataSource.connection.use { connection ->
                connection.prepareStatement(
                    "select version from ${CloakSchema.NAME}.${CloakSchema.HISTORY_TABLE} " +
                        "where success and version is not null order by installed_rank desc limit 1",
                ).use { statement ->
                    statement.queryTimeout = HEALTH_QUERY_SECONDS
                    statement.executeQuery().use { rows -> rows.next() && rows.getString(1) == CloakSchema.LATEST_VERSION }
                }
            }
        } catch (_: java.sql.SQLException) {
            false
        }

    /** Seconds a health query may take. */
    private const val HEALTH_QUERY_SECONDS = 2
}
