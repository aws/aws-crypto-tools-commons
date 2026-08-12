pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "mpl-test-server-tests"

includeBuild("../client-java") {
    dependencySubstitution {
        substitute(module("aws.cryptography.mpl.testserver:mpl-test-server-client-java"))
            .using(project(":"))
    }
}
