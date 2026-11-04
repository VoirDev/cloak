package dev.voir.cloak.spring

import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.observability.CloakEvents
import dev.voir.cloak.server.persistence.CloakMigrations
import dev.voir.cloak.spring.guard.CloakRequestGuard
import dev.voir.cloak.spring.observability.CloakHealthIndicator
import dev.voir.cloak.spring.observability.MicrometerCloakEvents
import dev.voir.cloak.spring.web.CloakPaths
import dev.voir.cloak.spring.web.CloakRequestInterceptor
import dev.voir.cloak.spring.web.RequestSizeFilter
import io.micrometer.core.instrument.MeterRegistry
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.health.contributor.HealthIndicator
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import dev.voir.cloak.spring.auth.CloakPrincipalResolver
import dev.voir.cloak.spring.web.Callers
import dev.voir.cloak.spring.web.CloakExceptionHandler
import dev.voir.cloak.spring.web.CloakJsonConverter
import dev.voir.cloak.spring.web.IdentityController
import dev.voir.cloak.spring.web.MemberController
import dev.voir.cloak.spring.web.SectionController
import dev.voir.cloak.spring.web.VaultController
import dev.voir.cloak.spring.web.VaultGroupController
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.http.converter.HttpMessageConverters
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import javax.sql.DataSource
import kotlin.time.Instant
import kotlin.time.toKotlinInstant

/**
 * Serves the Cloak API under `/cloak/v1` in a servlet application with a `DataSource`.
 *
 * The host must declare a [CloakPrincipalResolver]; startup fails without one. It may also
 * declare a `java.time.Clock`, a [CloakRequestGuard] to limit requests, and any number of
 * [CloakEvents] listeners. With Micrometer on the classpath, Cloak's events become meters in the
 * host's `MeterRegistry`; with Spring Boot's health support, a `cloak` health indicator reports
 * whether the database answers and its schema is current.
 *
 * Every Cloak request passes a size limit (`cloak.max-request-size`) before its body is read, and
 * one interceptor that resolves the caller, asks the guard and refuses deleted users.
 */
@AutoConfiguration(after = [DataSourceAutoConfiguration::class])
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(DataSource::class)
@EnableConfigurationProperties(CloakProperties::class)
public class CloakAutoConfiguration {
    /**
     * Migrates the `cloak` schema (unless disabled) and creates the server.
     *
     * @param dataSource Host's database.
     * @param properties Cloak settings.
     * @param clock Host's clock, if any.
     * @return The server.
     */
    @Bean
    @ConditionalOnMissingBean
    public fun cloakServer(
        dataSource: DataSource,
        properties: CloakProperties,
        clock: ObjectProvider<java.time.Clock>,
        events: ObjectProvider<CloakEvents>,
    ): CloakServer {
        val requestBytes = properties.maxRequestSize.toBytes()
        require(requestBytes <= Int.MAX_VALUE) { "cloak.max-request-size must be below 2GB." }
        // Checked before migrating, so a wrong limit fails startup before it touches the database.
        val settings = CloakSettings.builder()
            .maxRequestBytes(requestBytes.toInt())
            .statementTimeout(properties.database.statementTimeout)
            .checkpointStatementTimeout(properties.database.checkpointStatementTimeout)
            .lockTimeout(properties.database.lockTimeout)
            .maxStoredSectionsPerVault(properties.maxStoredSectionsPerVault)
            .maxPendingInvitations(properties.maxPendingInvitations)
            .maxPendingInvitationsPerInviter(properties.maxPendingInvitationsPerInviter)
            .writePause(properties.writePause.duration)
            .writePauseInterval(properties.writePause.interval)
            .events(CloakEvents.of(events.orderedStream().toList()))
            .build()
        if (properties.migrateOnStartup) CloakMigrations.migrate(dataSource)
        val javaClock = clock.getIfAvailable { java.time.Clock.systemUTC() }
        return CloakServer(
            dataSource = dataSource,
            clock = object : kotlin.time.Clock {
                override fun now(): Instant = javaClock.instant().toKotlinInstant()
            },
            settings = settings,
        )
    }

    /**
     * Resolves callers through the host's principal resolver.
     *
     * @param resolver Host's principal resolver.
     * @return The resolver of callers.
     */
    @Bean
    internal fun cloakCallers(resolver: ObjectProvider<CloakPrincipalResolver>): Callers =
        Callers(
            resolver.getIfAvailable()
                ?: error("Cloak needs a CloakPrincipalResolver bean that maps a request to the host's user id."),
        )

    /**
     * Meta, identity and user endpoints.
     *
     * @param server Cloak operations.
     * @param callers Caller resolution.
     * @return The controller.
     */
    @Bean
    internal fun cloakIdentityController(server: CloakServer, callers: Callers): IdentityController =
        IdentityController(server, callers)

    /**
     * Vault, log, key and checkpoint endpoints.
     *
     * @param server Cloak operations.
     * @param callers Caller resolution.
     * @return The controller.
     */
    @Bean
    internal fun cloakVaultController(server: CloakServer, callers: Callers): VaultController =
        VaultController(server, callers)

    /**
     * Member, envelope, departure, rotation and key replacement endpoints.
     *
     * @param server Cloak operations.
     * @param callers Caller resolution.
     * @return The controller.
     */
    @Bean
    internal fun cloakMemberController(server: CloakServer, callers: Callers): MemberController =
        MemberController(server, callers)

    /**
     * Endpoints over several vaults: batch rotations and write pauses.
     *
     * @param server Cloak operations.
     * @param callers Caller resolution.
     * @return The controller.
     */
    @Bean
    internal fun cloakVaultGroupController(server: CloakServer, callers: Callers): VaultGroupController =
        VaultGroupController(server, callers)

    /**
     * Section and node endpoints.
     *
     * @param server Cloak operations.
     * @param callers Caller resolution.
     * @return The controller.
     */
    @Bean
    internal fun cloakSectionController(server: CloakServer, callers: Callers): SectionController =
        SectionController(server, callers)

    /**
     * Registers [CloakJsonConverter] ahead of the host's converters, and the interceptor that
     * admits Cloak requests. The converter only handles Cloak's generated models, so the host's own
     * endpoints keep the host's JSON settings; the interceptor only acts on Cloak's handlers.
     *
     * @param server Cloak operations.
     * @param callers Caller resolution.
     * @param guard The host's request guard, if any.
     * @return The MVC configurer.
     */
    @Bean
    internal fun cloakWebMvcConfigurer(server: CloakServer, callers: Callers, guard: ObjectProvider<CloakRequestGuard>): WebMvcConfigurer =
        object : WebMvcConfigurer {
            override fun configureMessageConverters(builder: HttpMessageConverters.ServerBuilder) {
                builder.addCustomConverter(CloakJsonConverter())
            }

            override fun addInterceptors(registry: InterceptorRegistry) {
                registry.addInterceptor(CloakRequestInterceptor(server, callers, guard.ifAvailable))
                    .addPathPatterns("${CloakPaths.BASE}/**")
            }
        }

    /**
     * Refuses Cloak request bodies over the size limit before they are read.
     *
     * @param server Cloak operations, whose settings hold the limit.
     * @return The filter, on Cloak's paths only.
     */
    @Bean
    internal fun cloakRequestSizeFilter(server: CloakServer): FilterRegistrationBean<RequestSizeFilter> =
        FilterRegistrationBean(RequestSizeFilter(server.meta().limits.maxRequestBytes)).apply {
            addUrlPatterns("${CloakPaths.BASE}/*")
            order = Ordered.HIGHEST_PRECEDENCE + REQUEST_SIZE_FILTER_ORDER
        }

    /**
     * Problem rendering for the Cloak controllers.
     *
     * @return The handler.
     */
    @Bean
    internal fun cloakExceptionHandler(): CloakExceptionHandler = CloakExceptionHandler()

    /** Cloak's events as Micrometer meters, when Micrometer is on the classpath. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = ["io.micrometer.core.instrument.MeterRegistry"])
    internal class CloakMetricsConfiguration {
        /**
         * Reports Cloak's events to the host's registry, when it has one.
         *
         * @param registry The host's meter registry, if any.
         * @return The listener.
         */
        @Bean
        fun cloakMicrometerEvents(registry: ObjectProvider<MeterRegistry>): CloakEvents = MicrometerCloakEvents(registry)
    }

    /** Cloak's health indicator, when Spring Boot's health support is on the classpath. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = ["org.springframework.boot.health.contributor.HealthIndicator"])
    internal class CloakHealthConfiguration {
        /**
         * The `cloak` health contributor.
         *
         * @param dataSource The host's database.
         * @return The indicator.
         */
        @Bean("cloak")
        @ConditionalOnMissingBean(name = ["cloak"])
        fun cloakHealthIndicator(dataSource: DataSource): HealthIndicator = CloakHealthIndicator(dataSource)
    }

    /** Ordering. */
    private companion object {
        /** Place of the size filter after the very first filters, such as a host's tracing filter. */
        const val REQUEST_SIZE_FILTER_ORDER = 100
    }
}
