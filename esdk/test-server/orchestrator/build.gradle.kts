// The ESDK TestServer orchestrator / runner.
//
// This module is the closure
//   ESDKTestServer(Optional<LiveSource>, List<Override>) -> Result
// over the Configuration_Set. Its responsibilities, in order (design
// "The Closure / Orchestrator"):
//   1. Load + validate the Configuration_Set (Requirements 9.1-9.3, 9.5).
//   2. Resolve each language to one effective source: live / submodule /
//      artifact / head, enforcing single-mode-per-language and
//      single-live-language (Requirements 10-12).
//   3. Build + launch each server on its configured port; surface build
//      failures and port conflicts as aborts (Requirements 9.4, 9.6, 11.4, 12.8).
//   4. Point the single Java `Tests` at the launched endpoints via runtime
//      configuration only; refuse to run without configuration; abort on
//      duplicate `Tests` definitions (Requirements 7.2-7.5).
//   5. Report a fail-open Result (Requirements 11.3, 13.1-13.4).
//
// The concrete build/launch/test-run for the FIRST pass wires only the Java
// server end-to-end; git/artifact resolution for the Other languages sits behind
// abstractions (real cloning is task 11), so the pure-logic property tests use
// fakes.
plugins {
    application
}

repositories {
    // mavenLocal() FIRST so a live ESDK build installed to the local Maven repo
    // (task 11: aws-crypto-tools-java `build-live-esdk`, version e.g.
    // 3.0.2-LIVE-SNAPSHOT passed via -PesdkVersion) is consumed here as the
    // effective Java source in live mode. The orchestrator's runtimeClasspath
    // pulls the ESDK transitively from the included servers/java build, and that
    // resolution uses THIS project's repositories, so mavenLocal must be present
    // here as well as in servers/java. Default/head runs resolve the published
    // GA artifact from Maven Central below (Requirements 11.1, 11.2, 12.1).
    mavenLocal()
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Build/run with a JDK 21+ (set JAVA_HOME
// to a JDK 21 or newer), mirroring the other modules. No toolchain is pinned so
// the configured JDK 21+ is used.

val smithyJavaVersion: String by project
val jacksonVersion: String by project
val jqwikVersion: String by project
val junitVersion: String by project

dependencies {
    // --- The Java Language_Server (booted in-process on its configured port) --
    // Provides EsdkTestServerHandlers.service(), wired to the real ESDK. Consumed
    // from the ../servers/java included build so the wire contract stays single-
    // sourced (Requirements 7.2, 7.3, 9.4).
    implementation("aws.cryptography.esdk.testserver:esdk-test-server-java")

    // --- Server runtime: the Netty HTTP server that hosts the service ---------
    // server-api provides Server/ServerBuilder (compile); server-netty provides
    // the ServerProvider SPI implementation (runtime).
    implementation("software.amazon.smithy.java:server-api:$smithyJavaVersion")
    runtimeOnly("software.amazon.smithy.java:server-netty:$smithyJavaVersion")

    // --- Configuration_Set parsing --------------------------------------------
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")

    // --- Test frameworks ------------------------------------------------------
    // jqwik: pure-logic property tests (Properties 11-14). JUnit 5: integration
    // and example tests (port binding/conflict, orchestrator error paths).
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

application {
    // The runnable closure entrypoint. Invoked by the Makefile / CI to run the
    // orchestrator end-to-end.
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
