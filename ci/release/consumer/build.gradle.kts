plugins {
    java
    application
}

/** The staged Maven repository, `-PstagedRepository=<directory>`. */
val stagedRepository: String = providers.gradleProperty("stagedRepository").get()

/** The version the staged artifacts must carry, `-PreleaseVersion=<MAJOR.MINOR.PATCH>`. */
val releaseVersion: String = providers.gradleProperty("releaseVersion").get()

repositories {
    // Cloak's artifacts come from the staged repository and nowhere else; their dependencies from
    // Maven Central, as a host resolves them.
    exclusiveContent {
        forRepository { maven { url = uri(stagedRepository) } }
        filter { includeGroup("dev.voir.cloak") }
    }
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

dependencies {
    implementation("dev.voir.cloak:cloak-spring-boot-starter:$releaseVersion")
    implementation("dev.voir.cloak:cloak-server-core:$releaseVersion")
    implementation("dev.voir.cloak:cloak-api-models:$releaseVersion")
}

application {
    mainClass = "dev.voir.cloak.release.ReleaseCheck"
}

tasks.named<JavaExec>("run") {
    args(releaseVersion)
}
