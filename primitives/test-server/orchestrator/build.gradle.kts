plugins {
    application
}

repositories {
    mavenCentral()
}

val jacksonVersion: String by project
val junitVersion: String by project

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

application {
    mainClass.set("aws.cryptography.primitives.testserver.orchestrator.PrimitivesTestServerMain")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}
