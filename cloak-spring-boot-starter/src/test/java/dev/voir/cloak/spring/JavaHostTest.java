package dev.voir.cloak.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.voir.cloak.server.CloakServer;
import dev.voir.cloak.server.CloakSettings;
import dev.voir.cloak.server.identity.domain.HostUserId;
import dev.voir.cloak.server.meta.Limits;
import dev.voir.cloak.server.observability.CloakEvents;
import dev.voir.cloak.spring.guard.CloakRequestGuard;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import kotlin.time.Clock;
import dev.voir.cloak.server.persistence.CloakMigrations;
import dev.voir.cloak.server.testing.TestPostgres;
import dev.voir.cloak.spring.auth.CloakPrincipalResolver;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * A host written in Java: it implements the resolver and checks access through the host-facing
 * API without any Kotlin-only type, so a change that mangles those signatures fails to compile.
 */
class JavaHostTest {
    @Test
    void aJavaHostResolvesCallersAndChecksAccess() {
        CloakPrincipalResolver resolver = request -> request.getHeader("X-Host-User");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Host-User", "java-user@example.com");
        assertEquals("java-user@example.com", resolver.resolve(request));

        DataSource dataSource = TestPostgres.INSTANCE.getDataSource();
        CloakMigrations.migrate(dataSource);
        CloakServer cloak = new CloakServer(dataSource);
        assertNull(cloak.getAccess().role("java-user@example.com", UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class, () -> cloak.getAccess().role("", UUID.randomUUID()));
        assertFalse(cloak.getIdentity().erase(HostUserId.of("never-registered@example.com")));
        assertTrue(CloakMigrations.isSchemaCurrent(dataSource));
    }

    @Test
    void aJavaHostTunesTheServerAndListensToIt() {
        List<String> outcomes = new ArrayList<>();
        CloakEvents events = new CloakEvents() {
            @Override
            public void operationCompleted(String operation, String outcome, Duration duration) {
                outcomes.add(operation + " " + outcome);
            }
        };
        CloakSettings settings = CloakSettings.builder()
            .maxRequestBytes(Limits.MIN_REQUEST_BYTES)
            .statementTimeout(Duration.ofSeconds(2))
            .lockTimeout(Duration.ofSeconds(1))
            .events(CloakEvents.of(List.of(events)))
            .build();
        CloakServer cloak = new CloakServer(TestPostgres.INSTANCE.getDataSource(), Clock.System.INSTANCE, settings);

        assertEquals(Limits.MIN_REQUEST_BYTES, cloak.meta().getLimits().getMaxRequestBytes());
        assertThrows(IllegalArgumentException.class, () -> CloakSettings.builder().maxRequestBytes(1).build());
        CloakRequestGuard guard = (principal, operationId) -> operationId.equals("rotateVault") ? Duration.ofSeconds(1) : null;
        assertNull(guard.check("java-user@example.com", "getIdentity"));
    }
}
