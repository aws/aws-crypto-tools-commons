// The single ESDK TestServer `Tests` suite (Requirement 7.1).
//
// This module contains exactly one definition of the Tests. It drives every
// Language_Server exclusively through the ONE generated Java Test_Client
// (Requirement 1.6); it never regenerates a client and never contains a
// per-language client. Target endpoints come from runtime configuration only,
// so pointing the Tests at a different Language_Server is a configuration change
// with no change to the Tests definition (Requirements 7.2, 7.3).
//
// There is no `main` source set: the harness IS the tests (Requirement 13.5).
plugins {
    `java`
}

repositories {
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Build/run with a JDK 21+ (set JAVA_HOME
// to a JDK 21 or newer when invoking Gradle), mirroring the client and server
// modules. No toolchain is pinned so the configured JDK 21+ is used.

val smithyJavaVersion: String by project
val jqwikVersion: String by project
val junitVersion: String by project

dependencies {
    // --- The one generated Java Test_Client (Requirement 1.6) ---------------
    // Consumed from the ../client-java included build; this is the only client
    // the Tests use.
    testImplementation("aws.cryptography.esdk.testserver:esdk-test-server-client-java")

    // --- The Java Language_Server (booted in-process for the checkpoint) -----
    // Provides EsdkTestServerHandlers.service(), wired to the real ESDK. The
    // Tests target it over the wire; later phases target remote endpoints via
    // runtime config with no change to the Tests (Requirements 7.2, 7.3).
    testImplementation("aws.cryptography.esdk.testserver:esdk-test-server-java")

    // --- Client runtime: rpcv2Cbor protocol + JDK HTTP transport ------------
    // client-java exposes these as `implementation`, so declare them here for
    // compile access to the client builder, protocol, and transport types.
    testImplementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-rpcv2-cbor:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-http:$smithyJavaVersion")

    // --- Server runtime: the Netty HTTP server that hosts the service -------
    // server-api provides Server/ServerBuilder (compile); server-netty provides
    // the ServerProvider SPI implementation (runtime); server-rpcv2-cbor (pulled
    // transitively via the server module) provides the wire protocol.
    testImplementation("software.amazon.smithy.java:server-api:$smithyJavaVersion")
    testRuntimeOnly("software.amazon.smithy.java:server-netty:$smithyJavaVersion")

    // --- Test frameworks ----------------------------------------------------
    // jqwik: property-based testing (Property 1). JUnit 5: example-based tests.
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    // junit-jupiter-params powers the deterministic per-scenario parameterized
    // blob round-trip Test (Task 14.3): one named execution per keyring/CMM/
    // algorithm-suite scenario.
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        // jqwik registers its own JUnit Platform engine; include it explicitly.
        includeEngines("jqwik", "junit-jupiter")
    }
    // Surface which runtime endpoint configuration was used (helpful when the
    // orchestrator later points the Tests at remote Language_Servers).
    systemProperties(
        System.getProperties()
            .stringPropertyNames()
            .filter { it.startsWith("esdk.testserver.") }
            .associateWith { System.getProperty(it) }
    )
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
