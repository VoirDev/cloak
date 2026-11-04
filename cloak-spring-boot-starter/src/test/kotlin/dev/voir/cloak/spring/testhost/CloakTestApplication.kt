package dev.voir.cloak.spring.testhost

import dev.voir.cloak.server.testing.TestPostgres
import dev.voir.cloak.spring.auth.CloakPrincipalResolver
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import javax.sql.DataSource

/**
 * A minimal host: its "authentication" is the `X-Test-User` header, and its database is the
 * shared test container with a fresh `cloak` schema.
 */
@SpringBootApplication(proxyBeanMethods = false)
class CloakTestApplication {
    @Bean
    fun dataSource(): DataSource = TestPostgres.freshDataSource()

    @Bean
    fun principalResolver(): CloakPrincipalResolver =
        CloakPrincipalResolver { request -> request.getHeader(USER_HEADER) }

    companion object {
        /** Header the test host trusts as its session. */
        const val USER_HEADER = "X-Test-User"
    }
}
