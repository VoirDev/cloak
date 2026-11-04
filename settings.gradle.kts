pluginManagement {
    includeBuild("build-logic")
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
    }
}

rootProject.name = "cloak"

include(":cloak-api-models")
include(":cloak-server-core")
include(":cloak-spring-boot-starter")
include(":cloak-dev-server")
