pluginManagement {
    val smithyGradleVersion: String by settings
    plugins {
        id("software.amazon.smithy.gradle.smithy-base").version(smithyGradleVersion)
    }
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "mpl-test-server-client-java"
