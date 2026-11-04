// Convention for every Cloak artifact a release publishes to GitHub Packages: one Maven
// publication of the module's Java component with its sources, a POM that names the repository and
// the license, and the `release` repository that ci/release stages every artifact into before
// anything leaves the machine. A module is published only when it applies this plugin.
//
// The version is VERSION at the repository root, or `-PreleaseVersion`, which the release scripts
// pass. `-PreleaseRevision` writes the commit a release is built from into each POM as
// `cloak.revision`; an ordinary build leaves it out.

plugins {
    `java-library`
    `maven-publish`
}

/** The repository on GitHub: where the source lives, and the owner of its packages. */
val sourceRepositoryUrl = "https://github.com/VoirDev/cloak"

version =
    providers
        .gradleProperty("releaseVersion")
        .orElse(providers.fileContents(layout.settingsDirectory.file("VERSION")).asText.map { it.trim() })
        .get()

/** The commit a release is built from; only the release scripts set it. */
val releaseRevision = providers.gradleProperty("releaseRevision")

java {
    // Sources travel with the artifact, so a host stepping into Cloak in a debugger lands in the code.
    withSourcesJar()
}

// Test fixtures are for Cloak's own tests, not a published contract.
plugins.withId("java-test-fixtures") {
    val component = components["java"] as AdhocComponentWithVariants
    component.withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
    component.withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
}

publishing {
    publications {
        register<MavenPublication>("maven") {
            from(components["java"])
            // Versions a BOM supplies at build time are written out, so a host resolves every
            // dependency without importing that BOM itself.
            versionMapping {
                usage("java-api") { fromResolutionOf("runtimeClasspath") }
                usage("java-runtime") { fromResolutionResult() }
            }
            pom {
                name.set(project.name)
                description.set(provider { checkNotNull(project.description) { "${project.path} needs a description." } })
                url.set(sourceRepositoryUrl)
                licenses {
                    license {
                        name.set("Apache License 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                scm {
                    url.set(sourceRepositoryUrl)
                    connection.set("scm:git:$sourceRepositoryUrl.git")
                    developerConnection.set("scm:git:$sourceRepositoryUrl.git")
                }
                releaseRevision.orNull?.let { properties.put("cloak.revision", it) }
            }
        }
    }
    repositories {
        maven {
            name = "release"
            url = uri(layout.settingsDirectory.dir("build/release/repository"))
        }
    }
}
