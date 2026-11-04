// Convention for modules whose Kotlin sources are generated from an OpenAPI spec by fabrikt.
// Generated code is not hand-maintained, so explicit API mode and warnings-as-errors are off.

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("ch.acanda.gradle.fabrikt")
    `java-library`
}

group = "dev.voir.cloak"

kotlin {
    jvmToolchain(21)
}

// Generate before anything compiles or packs the sources, so IDE sync and builds see the same models.
tasks.named("compileKotlin") {
    dependsOn("fabriktGenerate")
}
tasks.matching { it.name == "sourcesJar" }.configureEach {
    dependsOn("fabriktGenerate")
}
