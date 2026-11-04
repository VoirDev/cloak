package dev.voir.cloak.spring

import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.testing.TestPostgres
import dev.voir.cloak.spring.auth.CloakPrincipalResolver
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.FilteredClassLoader
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** What the auto-configuration requires from the host and what it offers in return. */
class CloakAutoConfigurationTest {
    private val runner = WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(CloakAutoConfiguration::class.java))
        .withBean(DataSource::class.java, { TestPostgres.freshDataSource() })

    @Test
    fun `startup fails without a principal resolver`() {
        runner.run { context ->
            val failure = assertNotNull(context.startupFailure)
            val messages = generateSequence<Throwable>(failure) { it.cause }.map { it.message.orEmpty() }
            assertTrue(messages.any { "CloakPrincipalResolver" in it })
        }
    }

    @Test
    fun `a host with a resolver gets the server`() {
        runner.withBean(CloakPrincipalResolver::class.java, { CloakPrincipalResolver { "host-user" } }).run { context ->
            assertNotNull(context.getBean(CloakServer::class.java))
        }
    }

    @Test
    fun `startup fails with a request size limit the largest rotation would not fit in`() {
        runner.withBean(CloakPrincipalResolver::class.java, { CloakPrincipalResolver { "host-user" } })
            .withPropertyValues("cloak.max-request-size=1MB")
            .run { context ->
                val failure = assertNotNull(context.startupFailure)
                val messages = generateSequence<Throwable>(failure) { it.cause }.map { it.message.orEmpty() }
                assertTrue(messages.any { "rotation" in it })
            }
    }

    @Test
    fun `the pending invitations limit comes from the properties and shows in meta`() {
        runner.withBean(CloakPrincipalResolver::class.java, { CloakPrincipalResolver { "host-user" } })
            .withPropertyValues("cloak.max-pending-invitations=7")
            .run { context ->
                assertEquals(7, context.getBean(CloakServer::class.java).meta().limits.maxPendingInvitations)
            }
    }

    @Test
    fun `without Micrometer or health support the host gets neither, and still starts`() {
        runner.withBean(CloakPrincipalResolver::class.java, { CloakPrincipalResolver { "host-user" } })
            .withClassLoader(FilteredClassLoader("io.micrometer.core", "org.springframework.boot.health"))
            .run { context ->
                assertNull(context.startupFailure)
                assertFalse(context.containsBean("cloakMicrometerEvents"))
                assertFalse(context.containsBean("cloak"))
            }
    }

    @Test
    fun `with them the host gets Cloak's meters and health`() {
        runner.withBean(CloakPrincipalResolver::class.java, { CloakPrincipalResolver { "host-user" } }).run { context ->
            assertTrue(context.containsBean("cloakMicrometerEvents"))
            assertTrue(context.containsBean("cloak"))
        }
    }
}
