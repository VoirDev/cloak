// A consumer of the staged release, built only by ci/release/build-artifacts: it resolves Cloak's
// artifacts from the staged Maven repository alone, as a host application would from GitHub
// Packages, and runs them. It is written in Java, so it also shows a Java host can use them.
rootProject.name = "cloak-release-consumer"

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            from(files("../../../gradle/libs.versions.toml"))
        }
    }
}
