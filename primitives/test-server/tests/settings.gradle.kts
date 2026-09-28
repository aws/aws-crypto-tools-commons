// The single Primitives TestServer `Tests` suite. There is exactly one
// definition of the Tests, here, with zero per-language duplicate copies.
//
// The suite drives every Language_Server through the ONE generated Java
// Test_Client (../client-java) and never through a per-language client. To
// keep that client the single source of the wire contract, this module
// consumes the generated client as a Gradle composite ("included") build
// rather than regenerating any client here.
//
// The Tests are endpoint-only: every Language_Server is located exclusively
// through the `testserver.targets` runtime configuration supplied by the
// shared orchestrator. No Language_Server build is included here, so
// relocating a server requires zero changes to this module.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "primitives-test-server-tests"

// The one and only generated Java Test_Client.
includeBuild("../client-java") {
    dependencySubstitution {
        substitute(module("aws.cryptography.primitives.testserver:primitives-test-server-client-java"))
            .using(project(":"))
    }
}

// The shared TestServer test-support (FeatureGate, KnownBugGate, TargetPair,
// LanguageServerTarget/Registry, TestServerClientCache, etc.), consumed from
// the top-level test-server-common/ tree. The primitives-specific wrapper
// (PrimitivesTestServerClients) lives in this Tests module.
includeBuild("../../../test-server-common/tests-support") {
    dependencySubstitution {
        substitute(module("aws.cryptography.testserver:commons-test-server-tests-support"))
            .using(project(":"))
    }
}
