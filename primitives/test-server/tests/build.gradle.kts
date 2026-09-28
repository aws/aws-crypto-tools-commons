// The single Primitives TestServer Tests suite.
// No main source set: the harness IS the tests.
plugins {
    `java`
}

repositories {
    mavenCentral()
}

val smithyJavaVersion: String by project
val junitVersion: String by project

dependencies {
    // --- The one generated Java Test_Client -------------------------------
    // Consumed from the ../client-java included build; this is the only client
    // the Tests use.
    testImplementation("aws.cryptography.primitives.testserver:primitives-test-server-client-java")

    // --- Shared TestServer test-support ------------------------------------
    // Feature gates, endpoint registry, generic TestServerClientCache. The
    // primitives-local PrimitivesTestServerClients wraps it with the generated
    // client type.
    testImplementation("aws.cryptography.testserver:commons-test-server-tests-support")

    // --- Client runtime: rpcv2Cbor protocol + JDK HTTP transport -----------
    // client-java exposes these as `implementation`, so declare them here for
    // compile access to the client builder, protocol, and transport types.
    testImplementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-rpcv2-cbor:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-http:$smithyJavaVersion")

    // --- Test frameworks ----------------------------------------------------
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        includeEngines("junit-jupiter")
    }
    // Pass through the shared runner-emitted runtime configuration
    // (targets/features/featureCatalog/knownBugs/referenceImplementation).
    systemProperties(
        System.getProperties()
            .stringPropertyNames()
            .filter { it.startsWith("testserver.") }
            .associateWith { System.getProperty(it) }
    )
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
