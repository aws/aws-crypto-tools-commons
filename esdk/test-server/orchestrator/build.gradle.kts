// The ESDK TestServer orchestrator / runner.
//
// This module is the orchestrated pipeline over the Configuration_Set, the
// RunContext, and any Configuration_Overrides (design "Orchestrator core"):
//   1. Load + validate the Configuration_Set (product, Feature_Catalog,
//      entries) and the on-hand Feature_Declarations (Requirements 3, 7, 8).
//   2. Plan each component's source purely from the effective configuration
//      and the execution context, then materialize the plans with git
//      (Requirements 3.3-3.7, 4).
//   3. Build + launch every Language_Server as a SUBPROCESS from its resolved
//      source directory (JavaLaunchPlan / PythonLaunchPlan on the shared
//      SubprocessLauncher); surface build failures and port conflicts as
//      aborts (Requirements 2.1, 2.5).
//   4. Point the single `Tests` suite at the launched endpoints via runtime
//      configuration only (Requirement 10.2).
//   5. Report a fail-open Result (Requirements 2.8, 2.10).
//
// There is NO compile-time coupling to any Language_Server implementation:
// the former composite build of the Java server and its in-process launcher
// are gone (task 6.4) — server sources are resolved at run time from each
// entry's Server_Location (Requirement 1.5), e.g. the Java server from
// aws-crypto-tools-java at esdk/test-server/server.
plugins {
    application
}

repositories {
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Build/run with a JDK 21+ (set JAVA_HOME
// to a JDK 21 or newer), mirroring the other modules. No toolchain is pinned so
// the configured JDK 21+ is used.

val jacksonVersion: String by project
val jqwikVersion: String by project
val junitVersion: String by project

dependencies {
    // --- Configuration_Set parsing --------------------------------------------
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")

    // --- Test frameworks ------------------------------------------------------
    // jqwik: pure-logic property tests. JUnit 5: integration and example tests
    // (port binding/conflict, orchestrator error paths, real-git materialization).
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

application {
    // The runnable orchestrator entrypoint. Invoked by the Makefile / CI to run
    // the orchestrated pipeline end-to-end.
    mainClass.set("aws.cryptography.esdk.testserver.orchestrator.ESDKTestServerMain")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        // jqwik registers its own JUnit Platform engine; include it explicitly.
        includeEngines("jqwik", "junit-jupiter")
    }
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
