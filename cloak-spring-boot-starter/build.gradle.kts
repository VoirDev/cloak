plugins {
    id("cloak.kotlin-library")
    id("cloak.published")
}

description = "Spring Boot starter that serves the Cloak API under /cloak/v1 in a servlet host."

dependencies {
    implementation(platform(libs.spring.boot.dependencies))
    testImplementation(platform(libs.spring.boot.dependencies))

    api(project(":cloak-server-core"))
    api(project(":cloak-api-models"))
    api(libs.spring.boot.starter.webmvc)
    implementation(libs.spring.boot.starter.jdbc)
    implementation(libs.jackson.module.kotlin)
    implementation(libs.kotlin.reflect)
    // Optional: metrics and health appear when the host has them.
    compileOnly(libs.micrometer.core)
    compileOnly(libs.spring.boot.health)

    testImplementation(testFixtures(project(":cloak-server-core")))
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.webmvc.test)
    testImplementation(libs.json.schema.validator)
    testImplementation(libs.jackson2.dataformat.yaml)
    testImplementation(libs.micrometer.core)
    testImplementation(libs.spring.boot.health)
}

tasks.test {
    // The OpenAPI contract every response is validated against.
    systemProperty("cloak.openapi", layout.projectDirectory.file("../cloak-protocol/openapi/cloak-api.v1.yaml").asFile.path)
}
