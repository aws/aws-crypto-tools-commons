// The single ESDK TestServer `Tests` suite (Requirement 7.1). There is exactly
// one definition of the Tests, here, with zero per-language duplicate copies.
//
// The suite drives every Language_Server through the ONE generated Java
// Test_Client (../client-java, Requirement 1.6) and never through a
// per-language client. To keep that client the single source of the wire
// contract, this module consumes the generated client (and, for the Java-only
// checkpoint, the Java Language_Server) as Gradle composite ("included") builds
// rather than regenerating any client here.
//
// Explicit dependency substitution maps stable coordinates to the root project
// of each included build regardless of whether those builds declare a group, so
// `build.gradle.kts` can depend on them by coordinate.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "esdk-test-server-tests"

// The one and only generated Java Test_Client (Requirement 1.6).
includeBuild("../client-java") {
    dependencySubstitution {
        substitute(module("aws.cryptography.esdk.testserver:esdk-test-server-client-java"))
            .using(project(":"))
    }
}

// The Java Language_Server (smithy-java server codegen + real ESDK delegation).
// For the Java-only checkpoint the Tests boot this server in-process and target
// it over the wire; later phases target remote Language_Servers via runtime
// configuration only, with no change to the Tests (Requirements 7.2, 7.3).
includeBuild("../servers/java") {
    dependencySubstitution {
        substitute(module("aws.cryptography.esdk.testserver:esdk-test-server-java"))
            .using(project(":"))
    }
}
