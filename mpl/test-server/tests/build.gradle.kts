plugins {
    `java`
}

repositories {
    mavenCentral()
}

val smithyJavaVersion: String by project
val junitVersion: String by project

dependencies {
    testImplementation("aws.cryptography.mpl.testserver:mpl-test-server-client-java")

    testImplementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-rpcv2-cbor:$smithyJavaVersion")
    testImplementation("software.amazon.smithy.java:client-http:$smithyJavaVersion")

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
            .filter { it.startsWith("mpl.testserver.") }
            .associateWith { System.getProperty(it) }
    )
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
