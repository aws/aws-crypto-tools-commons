// The single ESDK TestServer `Tests` suite (Requirement 7.1). There is exactly
// one definition of the Tests, here, with zero per-language duplicate copies.
//
// The suite drives every Language_Server through the ONE generated Java
// Test_Client (../client-java, Requirement 1.6) and never through a
// per-language client. To keep that client the single source of the wire
// contract, this module consumes the generated client as a Gradle composite
// ("included") build rather than regenerating any client here.
//
// The Tests are endpoint-only: every Language_Server is located exclusively
// through the `esdk.testserver.targets` runtime configuration supplied by the
// orchestrator (Requirement 10.2). No Language_Server build is included here,
// so relocating a server requires zero changes to this module.
//
// Explicit dependency substitution maps stable coordinates to the root project
// of the included build regardless of whether that build declares a group, so
// `build.gradle.kts` can depend on it by coordinate.
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
