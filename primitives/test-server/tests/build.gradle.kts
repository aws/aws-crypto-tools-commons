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
    // --- The generated Java Test_Client ---
    testImplementation("aws.cryptography.primitives.testserver:primitives-test-server-client-java")

    // --- Client runtime: rpcv2Cbor protocol + JDK HTTP transport ---
    testImplementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-rpcv2-cbor:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-http:$smithyJavaVersion")

    // --- Test frameworks ---
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        includeEngines("junit-jupiter")
    }
    systemProperties(
        System.getProperties()
            .stringPropertyNames()
            .filter { it.startsWith("primitives.testserver.") }
            .associateWith { System.getProperty(it) }
    )
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
