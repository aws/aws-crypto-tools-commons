// Single generated Java Test_Client for the ESDK TestServer (Requirement 1.6).
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

rootProject.name = "dbesdk-test-server-client-java"
