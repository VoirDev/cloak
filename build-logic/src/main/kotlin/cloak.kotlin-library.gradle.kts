// Convention for every Cloak JVM library: Kotlin on a Java 21 toolchain, explicit API, JUnit.

plugins {
    id("org.jetbrains.kotlin.jvm")
    `java-library`
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

fun library(alias: String) = libs.findLibrary(alias).get()

group = "dev.voir.cloak"

kotlin {
    jvmToolchain(21)
    explicitApi()
    compilerOptions {
        allWarningsAsErrors = true
        optIn.add("kotlin.uuid.ExperimentalUuidApi")
        optIn.add("kotlin.time.ExperimentalTime")
    }
}

dependencies {
    testImplementation(platform(library("junit-bom")))
    testImplementation(library("junit-jupiter"))
    testImplementation(kotlin("test-junit5"))
    testRuntimeOnly(library("junit-platform-launcher"))
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
