plugins {
    id("cloak.kotlin-library")
    id("cloak.published")
    `java-test-fixtures`
}

description = "Framework-free Cloak server: schema, protocol checks and operations."

dependencies {
    api(libs.kotlinx.io.bytestring)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.exposed.kotlin.datetime)
    implementation(libs.flyway.core)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.flyway.database.postgresql)

    testFixturesApi(libs.testcontainers.postgresql)
    testFixturesApi(libs.postgresql)

    testImplementation(libs.exposed.migration.jdbc)
    testImplementation(libs.kotlinx.serialization.json)
}

kotlin {
    // Test fixtures sign like a real client, so they reuse the internal protocol builders.
    target.compilations.getByName("testFixtures").associateWith(target.compilations.getByName("main"))
}

tasks.test {
    // Shared protocol test vectors, read by the protocol tests.
    systemProperty("cloak.vectors", layout.projectDirectory.dir("../cloak-protocol/test-vectors/v1").asFile.path)
}
