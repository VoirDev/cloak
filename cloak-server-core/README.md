# cloak-server-core

The Cloak server without a web framework, for any JVM host: every check the protocol gives the
server, persistence in the PostgreSQL schema `cloak`, and its Flyway migrations. It never decrypts
anything and holds no keys. A Spring Boot host uses `cloak-spring-boot-starter`, which serves this
over HTTP.

```kotlin
CloakMigrations.migrate(dataSource) // once at startup, before serving requests
val cloak = CloakServer(dataSource, clock)
```

How to install, configure and run it, the host APIs and the data it keeps are in
[docs/backend.md](../docs/backend.md); its code layout and tests are in
[docs/development.md](../docs/development.md).
