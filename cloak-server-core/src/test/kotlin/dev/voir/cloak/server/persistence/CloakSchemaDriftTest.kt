package dev.voir.cloak.server.persistence

import dev.voir.cloak.server.testing.TestPostgres
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.migration.jdbc.MigrationUtils
import kotlin.test.Test
import kotlin.test.assertEquals

/** Checks that the Flyway migrations and the Exposed table declarations describe the same schema. */
class CloakSchemaDriftTest {
    @Test
    fun `migrated schema matches the Exposed declarations`() {
        val database = Database.connect(TestPostgres.freshDataSource())

        val statements = transaction(database) {
            MigrationUtils.statementsRequiredForDatabaseMigration(*CloakSchema.tables.toTypedArray())
        }

        assertEquals(emptyList(), statements)
    }

    @Test
    fun `migrating twice applies nothing the second time`() {
        TestPostgres.freshDataSource()

        assertEquals(0, CloakMigrations.migrate(TestPostgres.dataSource))
    }

    @Test
    fun `the declared latest version is the latest migration, and the health check sees it`() {
        val dataSource = TestPostgres.freshDataSource()
        // Gradle runs tests in the project directory, where the migrations are sources.
        val versions = java.io.File("src/main/resources/db/migration/cloak").list().orEmpty().mapNotNull { Regex("^V(\\d+)__.*\\.sql$").find(it)?.groupValues?.get(1)?.toInt() }

        assertEquals(versions.maxOrNull()?.toString(), CloakSchema.LATEST_VERSION)
        assertEquals(true, CloakMigrations.isSchemaCurrent(dataSource))
        dataSource.connection.use { it.createStatement().execute("update cloak.flyway_schema_history set version = '0'") }
        assertEquals(false, CloakMigrations.isSchemaCurrent(dataSource))
    }
}
