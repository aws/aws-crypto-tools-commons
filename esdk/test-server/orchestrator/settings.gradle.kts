// The ESDK TestServer orchestrator / runner (the closure over the
// Configuration_Set, source resolution, launch, and fail-open reporting).
//
// The orchestrator launches the Java Language_Server in-process (reusing the
// same EsdkTestServerHandlers.service() assembly point the checkpoint uses) and
// points the single Java `Tests` suite at the launched endpoint(s) purely
// through runtime configuration. To keep the wire contract single-sourced, it
// consumes the Java Language_Server as a Gradle composite ("included") build
// rather than duplicating any server code.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "esdk-test-server-orchestrator"

// The Java Language_Server (smithy-java server codegen + real ESDK delegation).
// The orchestrator boots this in-process on the port from its Configuration_Entry
// and drives the single Java `Tests` against it (Requirements 9.4, 7.2, 7.3).
includeBuild("../servers/java") {
    dependencySubstitution {
        substitute(module("aws.cryptography.esdk.testserver:esdk-test-server-java"))
            .using(project(":"))
    }
}
