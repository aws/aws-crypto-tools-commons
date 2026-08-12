pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "primitives-test-server-tests"

// The generated Java Test_Client.
includeBuild("../client-java") {
    dependencySubstitution {
        substitute(module("aws.cryptography.primitives.testserver:primitives-test-server-client-java"))
            .using(project(":"))
    }
}
