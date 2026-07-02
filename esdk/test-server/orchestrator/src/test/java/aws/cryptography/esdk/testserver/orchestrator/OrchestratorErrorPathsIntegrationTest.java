package aws.cryptography.esdk.testserver.orchestrator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.esdk.testserver.orchestrator.report.Result;
import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.GradleTestRunner;
import aws.cryptography.esdk.testserver.orchestrator.run.MissingRuntimeConfigException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Integration tests for the orchestrator's error paths (design Testing Strategy;
 * Requirements 7.4, 7.5, 10.4, 11.4, 12.8). Each aborts before running any
 * {@code Tests}, records no partial results, and returns a fail-open failure that
 * identifies the cause. Uses {@link FakeLauncher}/{@link StubTestRunner} so the
 * paths are deterministic without cloning repos or launching servers.
 */
class OrchestratorErrorPathsIntegrationTest {

    private static ConfigurationSet javaOnly() {
        return new ConfigurationSet(List.of(
            new ConfigurationEntry("java", "main", "aws-crypto-tools-java", 3, 8099)));
    }

    private static ESDKTestServer orchestrator(
            ConfigurationSet set, FakeLauncher launcher, StubTestRunner runner, Path root) {
        return new ESDKTestServer(set, launcher, runner, new DuplicateTestsDetector(), root);
    }

    @Test
    @DisplayName("unresolvable head aborts, names the language, runs no Tests (Req 10.4)")
    void unresolvableHeadAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.throwing(new ServerLaunchException(
            "java", ServerLaunchException.Category.UNRESOLVABLE_SOURCE,
            "cannot resolve head of branch main in aws-crypto-tools-java"));
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded(), "an unresolvable head must abort the run");
        assertTrue(result.summary().contains("java"), "the abort must name the language");
        assertTrue(result.summary().contains("UNRESOLVABLE_SOURCE"), "the abort must state the cause");
        assertFalse(runner.wasInvoked(), "no Tests may run on an aborted resolution (no partial results)");
    }

    @Test
    @DisplayName("unbuildable live source aborts, names the language, runs no Tests (Req 11.4)")
    void unbuildableLiveSourceAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.throwing(new ServerLaunchException(
            "java", ServerLaunchException.Category.BUILD_FAILURE,
            "live Java source failed to build"));
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("java"));
        assertTrue(result.summary().contains("BUILD_FAILURE"));
        assertFalse(runner.wasInvoked(), "no Tests may run when the live source cannot be built");
    }

    @Test
    @DisplayName("unavailable artifact / bad commit aborts identifying the reference (Req 12.8)")
    void unresolvableOverrideAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.throwing(new ServerLaunchException(
            "java", ServerLaunchException.Category.UNRESOLVABLE_SOURCE,
            "artifact version 9.9.9 is not available"));
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("9.9.9"), "the abort must identify the unresolvable reference");
        assertFalse(runner.wasInvoked());
    }

    @Test
    @DisplayName("absent runtime config aborts before Tests run, no partial results (Req 7.4)")
    void absentRuntimeConfigAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.refusing();

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded(), "refusing to run with no endpoint must be a failure");
        assertTrue(result.summary().toLowerCase().contains("no target endpoint")
                || result.details().toString().toLowerCase().contains("no target endpoint"),
            "the abort must indicate the missing runtime configuration: " + result.summary());
    }

    @Test
    @DisplayName("duplicate Tests definitions abort before Tests run (Req 7.5)")
    void duplicateTestsDefinitionsAbort(@TempDir Path root) throws IOException {
        // Two directories that each declare the canonical Tests root project.
        writeTestsMarker(root.resolve("tests"));
        writeTestsMarker(root.resolve("tests-copy"));

        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded(), "duplicate Tests definitions must abort the run");
        assertTrue(result.summary().contains("Tests definitions"),
            "the abort must call out duplicate Tests definitions: " + result.summary());
        Assertions.assertEquals(0, launcher.launchCount(), "no server may launch on duplicate Tests");
        assertFalse(runner.wasInvoked(), "no Tests may run when duplicates are detected");
    }

    @Test
    @DisplayName("invalid Configuration_Set aborts identifying the entry (Req 9.5)")
    void invalidConfigurationAborts(@TempDir Path root) {
        ConfigurationSet invalid = new ConfigurationSet(List.of(
            new ConfigurationEntry("java", "main", "aws-crypto-tools-java", 3, 70000))); // bad port
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(invalid, launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("out of range"), "must identify the invalid entry field");
        Assertions.assertEquals(0, launcher.launchCount(), "no server may launch on an invalid config");
    }

    @Test
    @DisplayName("GradleTestRunner refuses to run with no endpoint (Req 7.4)")
    void gradleRunnerRefusesWithoutEndpoint(@TempDir Path root) {
        GradleTestRunner runner = new GradleTestRunner(root.resolve("tests"));
        Assertions.assertThrows(MissingRuntimeConfigException.class,
            () -> runner.run(List.of()),
            "the runner must refuse to run when no endpoint is configured");
    }

    @Test
    @DisplayName("failed executed Tests report failure identifying the failed Test (Req 13.2)")
    void failedExecutedTestsReportFailure(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of(
            TestExecution.passed("RoundTrip#a"),
            TestExecution.failed("RoundTrip#b", "mismatch")));

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.details().toString().contains("RoundTrip#b"),
            "failure must identify the failed Test");
    }

    private static void writeTestsMarker(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("settings.gradle.kts"),
            "rootProject.name = \"" + DuplicateTestsDetector.TESTS_ROOT_NAME + "\"\n");
    }
}
