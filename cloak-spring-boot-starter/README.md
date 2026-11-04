# cloak-spring-boot-starter

Serves the Cloak API (`cloak-protocol/openapi/cloak-api.v1.yaml`) under `/cloak/v1` in a Spring
Boot 4 servlet application. All rules live in `cloak-server-core`; this module maps HTTP to it,
renders failures as RFC 9457 problems, and reports metrics and health.

The host provides a PostgreSQL `DataSource` and a `CloakPrincipalResolver` that names the caller by
the host's own user id:

```kotlin
@Bean
fun cloakPrincipalResolver(): CloakPrincipalResolver = CloakPrincipalResolver { request ->
    request.userPrincipal?.name // the host's user id, or null without a session
}
```

Installation, configuration, admission, host APIs and operations are in
[docs/backend.md](../docs/backend.md).
