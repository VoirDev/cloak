package dev.voir.cloak.spring.observability

import dev.voir.cloak.server.persistence.CloakMigrations
import org.springframework.boot.health.contributor.Health
import org.springframework.boot.health.contributor.HealthIndicator
import javax.sql.DataSource

/**
 * Cloak's health, as the `cloak` contributor of Spring Boot Actuator: up when the database answers
 * and its `cloak` schema is at the version this build expects, down otherwise. It reports no
 * detail, so a public health endpoint says nothing about the database.
 *
 * @property dataSource The host's database.
 */
internal class CloakHealthIndicator(
    private val dataSource: DataSource,
) : HealthIndicator {
    /** Checks the database and the schema version. */
    override fun health(): Health =
        if (CloakMigrations.isSchemaCurrent(dataSource)) Health.up().build() else Health.down().build()
}
