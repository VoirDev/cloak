package dev.voir.cloak.devserver

import dev.voir.cloak.spring.auth.CloakPrincipalResolver
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.testcontainers.postgresql.PostgreSQLContainer
import javax.sql.DataSource

/**
 * A development host for client end-to-end tests. It is NOT secure: whoever sends
 * [USER_HEADER] is that user. Never deploy it.
 */
@SpringBootApplication(proxyBeanMethods = false)
internal class DevServer {
    /**
     * A fresh PostgreSQL in a container, removed when the JVM exits.
     *
     * @return Data source of the container.
     */
    @Bean
    fun dataSource(): DataSource {
        val container = PostgreSQLContainer("postgres:17-alpine").apply { start() }
        return DriverManagerDataSource(container.jdbcUrl, container.username, container.password)
    }

    /**
     * Trusts [USER_HEADER] as the session.
     *
     * @return The resolver.
     */
    @Bean
    fun principalResolver(): CloakPrincipalResolver =
        CloakPrincipalResolver { request -> request.getHeader(USER_HEADER) }

    /** Constants of the development host. */
    internal companion object {
        /** Header the development host trusts as the caller's host user id, any string. */
        const val USER_HEADER: String = "X-Cloak-Dev-User"
    }
}

/**
 * Starts the development host; pass `--server.port=<port>` to choose the port.
 *
 * @param args Spring Boot arguments.
 */
public fun main(args: Array<String>) {
    runApplication<DevServer>(*args)
}
