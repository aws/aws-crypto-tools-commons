// Shared TestServer test-support: the runtime-config-reading gate/registry
// classes and the generic client cache each SDK's Tests suite consumes.
// Consumed by every per-SDK Tests module through `includeBuild("../tests-support")`
// with a dependency-substitution to this rootProject.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "commons-test-server-tests-support"
