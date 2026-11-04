plugins {
    id("cloak.kotlin-library")
    application
}

description = "A throwaway Spring Boot host for client end-to-end tests: Postgres in a container, trust-me auth."

dependencies {
    implementation(platform(libs.spring.boot.dependencies))
    implementation(project(":cloak-spring-boot-starter"))
    implementation(libs.spring.boot.starter.jdbc)
    implementation(libs.testcontainers.postgresql)
    runtimeOnly(libs.postgresql)
}

application {
    mainClass = "dev.voir.cloak.devserver.DevServerKt"
}
