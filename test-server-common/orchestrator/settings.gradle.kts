// The DB-ESDK TestServer orchestrator / runner (the closure over the
// commons configuration, source resolution, launch, and fail-open reporting).
//
// Every Language_Server is built and launched as a SUBPROCESS from its
// resolved source directory (JavaLaunchPlan / RustLaunchPlan on the shared
// SubprocessLauncher machinery) — the orchestrator has no compile-time
// coupling to any server implementation (Requirements 1.5, 2.7). The former
// in-process composite build of the Java server (once includeBuilt from this
// file) is gone: server sources are resolved at run time from each entry's
// Server_Location, which is what lets the language servers live in the
// aws-database-encryption-sdk-dynamodb product repo at all.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "commons-test-server-orchestrator"
