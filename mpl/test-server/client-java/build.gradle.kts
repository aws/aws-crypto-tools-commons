plugins {
    `java-library`
    id("software.amazon.smithy.gradle.smithy-base")
}

repositories {
    mavenCentral()
}

val smithyJavaVersion: String by project
val smithyProtocolTraitsVersion: String by project

dependencies {
    smithyBuild("software.amazon.smithy.java:codegen-plugin:$smithyJavaVersion")
    smithyBuild("software.amazon.smithy:smithy-protocol-traits:$smithyProtocolTraitsVersion")

    implementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")
    implementation("software.amazon.smithy.java:client-rpcv2-cbor:$smithyJavaVersion")
}

smithy {
    format.set(false)
}

sourceSets {
    main {
        smithy {
            srcDir("../model")
        }
    }
}

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

tasks.named("compileJava") {
    dependsOn("smithyBuild")
}

tasks.named("processResources") {
    dependsOn("smithyBuild")
}
