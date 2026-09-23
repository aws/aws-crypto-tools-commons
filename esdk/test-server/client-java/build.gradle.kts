// Builds the single, typed Java Test_Client for the ESDK TestServer service
// over the rpcv2Cbor protocol (Requirement 1.6). The client is generated from
// the single source-of-truth Smithy model at ../model by the smithy-java
// `java-codegen` build plugin, then compiled into this module.
//
// The TestServer generates exactly one client, and that client is Java; there
// is no per-language client (Requirement 1.6).

plugins {
    `java-library`
    // Runs the Smithy build (and thus the java-codegen plugin) during the
    // Gradle build. Version comes from gradle.properties via settings.
    id("software.amazon.smithy.gradle.smithy-base")
}

repositories {
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Build with a JDK 21+ (set JAVA_HOME to a
// JDK 21 or newer when invoking Gradle). We intentionally do not pin a Java
// toolchain version here so the build uses whatever compatible JDK 21+ is
// configured for Gradle in the environment / CI.

val smithyJavaVersion: String by project
val smithyProtocolTraitsVersion: String by project

dependencies {
    // --- Code generation (smithy build classpath only) ---
    // The smithy-java code generation plugins, discovered by the smithyBuild
    // task via SPI.
    smithyBuild("software.amazon.smithy.java:codegen-plugin:$smithyJavaVersion")
    // The rpcv2Cbor protocol trait definition must be resolvable while the
    // model is built so `smithy.protocols#rpcv2Cbor` is understood by codegen.
    smithyBuild("software.amazon.smithy:smithy-protocol-traits:$smithyProtocolTraitsVersion")

    // --- Runtime dependencies of the generated client ---
    // client-core is required by all generated smithy-java clients.
    implementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")
    // rpcv2Cbor client protocol implementation (marshalling/unmarshalling),
    // discovered at runtime via SPI; this is the protocol declared once at the
    // service level in the model.
    implementation("software.amazon.smithy.java:client-rpcv2-cbor:$smithyJavaVersion")
}

// The shared model is owned by the model/ package; this client only consumes
// it. Disable the formatter so building the client never rewrites the
// single source-of-truth model file (Requirement 1.1).
smithy {
    format.set(false)
}

// Use the single source-of-truth model (Requirement 1.1) rather than a copy.
sourceSets {
    main {
        smithy {
            srcDir("../model")
        }
    }
}

// Add the generated client sources/resources to the main sourceSet so they are
// compiled alongside this module.
afterEvaluate {
    val clientPath = smithy.getPluginProjectionPath(smithy.sourceProjection.get(), "java-codegen").get()
    sourceSets {
        main {
            java {
                srcDir("$clientPath/java")
            }
            resources {
                srcDir("$clientPath/resources")
            }
        }
    }
}

// Ensure code generation runs before compilation / resource processing.
tasks.named("compileJava") {
    dependsOn("smithyBuild")
}

tasks.named("processResources") {
    dependsOn("smithyBuild")
}
