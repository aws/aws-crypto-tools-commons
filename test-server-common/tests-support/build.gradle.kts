// Shared TestServer test-support: the classes each SDK's Tests suite consumes
// to observe Language_Server targets, gate Feature-associated Tests, gate
// expected-failure known bugs, and cache one client per endpoint. This module
// has NO compile-time dependency on any per-SDK generated Test_Client, model,
// or transport: TestServerClientCache is parameterized on the client type; the
// per-SDK builder function lives in each SDK's own thin wrapper. Every runtime
// property this module reads is on the product-neutral testserver.* namespace,
// so every SDK's Tests can consume the same registry / gate / cache without
// wiring an SDK-specific property surface.
plugins {
    `java`
}

repositories {
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Mirrors the other modules; no toolchain
// is pinned so the configured JDK 21+ is used.

val smithyJavaVersion: String by project
val jqwikVersion: String by project
val junitVersion: String by project

dependencies {
    // TestServerClientCache.withRetry catches software.amazon.smithy.java's
    // TransportException; every consuming Tests suite already declares
    // client-core, so this stays `implementation` — surfacing the exception on
    // downstream compile classpaths for anyone chaining withRetry.
    implementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")

    // KnownBugs parses the ledger JSON, and FeatureGate throws
    // TestAbortedException. Neither is a transitive concern of consumers, but
    // both must appear on the shared module's runtime classpath.
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("org.opentest4j:opentest4j:1.3.0")

    // KnownBugGate.gate takes an org.junit.jupiter.api.function.Executable —
    // JUnit's public functional-interface for a throwing lambda — so JUnit's
    // API must be on the shared module's own compile classpath. Downstream
    // Tests modules already declare junit-jupiter-api at testImplementation
    // level, so this stays `implementation` here (not `api`): consumers see
    // Executable through their own JUnit dep, not by transit from us.
    implementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")

    // Self-tests only.
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        includeEngines("jqwik", "junit-jupiter")
    }
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
