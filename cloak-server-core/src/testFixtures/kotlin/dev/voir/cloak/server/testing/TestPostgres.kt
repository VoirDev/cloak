package dev.voir.cloak.server.testing

import dev.voir.cloak.server.persistence.CloakMigrations
import org.postgresql.ds.PGSimpleDataSource
import org.testcontainers.postgresql.PostgreSQLContainer
import javax.sql.DataSource

/** One PostgreSQL container shared by every test in the JVM, with a fresh `cloak` schema per call. */
public object TestPostgres {
    /** Container started on first use; Testcontainers' Ryuk removes it when the JVM exits. */
    private val container: PostgreSQLContainer by lazy {
        PostgreSQLContainer("postgres:17-alpine").apply { start() }
    }

    /** Data source for the shared container. */
    public val dataSource: DataSource by lazy {
        PGSimpleDataSource().apply {
            setUrl(container.jdbcUrl)
            user = container.username
            password = container.password
        }
    }

    /**
     * Drops the `cloak` schema and migrates it from empty.
     *
     * @return The shared data source, whose `cloak` schema holds every migration and no rows.
     */
    public fun freshDataSource(): DataSource {
        dataSource.connection.use { connection ->
            connection.createStatement().use { it.execute("drop schema if exists cloak cascade") }
        }
        CloakMigrations.migrate(dataSource)
        return dataSource
    }
}
