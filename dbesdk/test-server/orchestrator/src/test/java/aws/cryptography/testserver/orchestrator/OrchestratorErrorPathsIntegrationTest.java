package aws.cryptography.testserver.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.testserver.orchestrator.config.ServerLocation;
import aws.cryptography.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.testserver.orchestrator.report.Result;
import aws.cryptography.testserver.orchestrator.report.TestExecution;
import aws.cryptography.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.testserver.orchestrator.run.GradleTestRunner;
import aws.cryptography.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.testserver.orchestrator.source.RunContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Integration tests for the orchestrator's fail-closed error paths (design
 * "Error Handling"). Each aborts before running any {@code Tests}, records no
 * partial results, and returns a fail-open failure that identifies the cause.
 * Uses {@link FakeLauncher}/{@link StubTestRunner} so the paths are
 * deterministic without cloning repos or launching servers.
 */
class OrchestratorErrorPathsIntegrationTest {

    /** A structurally complete entry (validation requires it). */
    private static ConfigurationEntry completeJavaEntry(int port) {
        return completeEntry("java", port);
    }

    /** A structurally complete entry for {@code language}, no inline declaration. */
    private static ConfigurationEntry completeEntry(String language, int port) {
        return new ConfigurationEntry(language, 3, port,
            new RepositoryCoordinates("aws-crypto-tools-" + language,
                "git@github.com:aws/aws-crypto-tools-" + language + ".git", "main", "esdk"),
            new ServerLocation("aws-crypto-tools-" + language,
                "git@github.com:aws/aws-crypto-tools-" + language + ".git", "main",
                "dbesdk/test-server/server"),
            null, null);
    }

    private static CommonsConfiguration javaOnly() {
        return new CommonsConfiguration("esdk", List.of("streaming", "MPL"),
            List.of(completeJavaEntry(8099)));
    }

    private static TestServerOrchestrator orchestrator(
            CommonsConfiguration set, FakeLauncher launcher, StubTestRunner runner, Path root) {
        RunContext context = RunContext.commonsRun(root, "aws-crypto-tools-commons");
        return new TestServerOrchestrator(set, context,
            FakeMaterializer.succeedingUnder(root, set),
            LauncherFactory.uniform(launcher), runner,
            new DuplicateTestsDetector(), root);
    }

    @Test
    @DisplayName("unresolvable head aborts, names the language, runs no Tests (Req 2.5)")
    void unresolvableHeadAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.throwing(new ServerLaunchException(
            "java", ServerLaunchException.Category.RESOLVE,
            "cannot resolve head of branch main in aws-database-encryption-sdk-dynamodb"));
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded(), "an unresolvable head must abort the run");
        assertTrue(result.summary().contains("java"), "the abort must name the language");
        assertTrue(result.summary().contains("RESOLVE"), "the abort must state the cause");
        assertFalse(runner.wasInvoked(), "no Tests may run on an aborted resolution (no partial results)");
    }

    @Test
    @DisplayName("unbuildable live source aborts, names the language, runs no Tests (Req 2.5)")
    void unbuildableLiveSourceAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.throwing(new ServerLaunchException(
            "java", ServerLaunchException.Category.BUILD,
            "live Java source failed to build"));
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("java"));
        assertTrue(result.summary().contains("BUILD"));
        assertFalse(runner.wasInvoked(), "no Tests may run when the live source cannot be built");
    }

    @Test
    @DisplayName("unresolvable launch reference aborts identifying the reference (Req 2.5)")
    void unresolvableOverrideAborts(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.throwing(new ServerLaunchException(
            "java", ServerLaunchException.Category.RESOLVE,
            "artifact version 9.9.9 is not available"));
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(javaOnly(), launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("9.9.9"), "the abort must identify the unresolvable reference");
        assertFalse(runner.wasInvoked());
    }

    @Test
    @DisplayName("absent runtime config aborts before Tests run, no partial results (Req 10.2)")
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
    @DisplayName("duplicate Tests definitions abort before Tests run (Req 10.1)")
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
    @DisplayName("invalid commons configuration aborts identifying the entry (Req 3.2)")
    void invalidConfigurationAborts(@TempDir Path root) {
        CommonsConfiguration invalid = new CommonsConfiguration("esdk", List.of("streaming", "MPL"),
            List.of(completeJavaEntry(70000))); // bad port
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(invalid, launcher, runner, root).run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("out of range"), "must identify the invalid entry field");
        Assertions.assertEquals(0, launcher.launchCount(), "no server may launch on an invalid config");
    }

    @Test
    @DisplayName("GradleTestRunner refuses to run with no target configured (Req 10.2)")
    void gradleRunnerRefusesWithoutEndpoint(@TempDir Path root) {
        GradleTestRunner runner = new GradleTestRunner(root.resolve("tests"));
        Assertions.assertThrows(MissingRuntimeConfigException.class,
            () -> runner.run(new TestRunInput(List.of(), Map.of(), List.of(), Map.of(), "java")),
            "the runner must refuse to run when no target is configured");
    }

    @Test
    @DisplayName("an unknown referenceImplementation aborts naming it and the configured languages")
    void unknownReferenceImplementationAborts(@TempDir Path root) {
        CommonsConfiguration set = javaOnly();
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of());
        RunContext context = RunContext.commonsRun(root, "aws-crypto-tools-commons");
        TestServerOrchestrator orchestrator = new TestServerOrchestrator(set, context,
            FakeMaterializer.succeedingUnder(root, set),
            LauncherFactory.uniform(launcher), runner,
            new DuplicateTestsDetector(), root, "ruby");

        Result result = orchestrator.run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("'ruby'"),
            "the abort must name the unknown value: " + result.summary());
        assertTrue(result.summary().contains("java"),
            "the abort must list the configured languages: " + result.summary());
        assertEquals(0, launcher.launchCount(), "no server may launch on an invalid reference");
        assertFalse(runner.wasInvoked(), "no Tests may run on an invalid reference");
    }

    @Test
    @DisplayName("the default referenceImplementation java reaches the Tests run")
    void defaultReferenceImplementationReachesTheTestsRun(@TempDir Path root) {
        StubTestRunner runner = StubTestRunner.returning(List.of(
            TestExecution.passed("RoundTrip#a")));

        orchestrator(javaOnly(), FakeLauncher.succeeding(), runner, root).run();

        assertTrue(runner.wasInvoked());
        assertEquals("java", runner.lastInput().referenceImplementation());
    }

    @Test
    @DisplayName("an explicit referenceImplementation reaches the Tests run")
    void explicitReferenceImplementationReachesTheTestsRun(@TempDir Path root) {
        CommonsConfiguration set = new CommonsConfiguration("esdk", List.of("streaming", "MPL"),
            List.of(completeJavaEntry(8091), completeEntry("python", 8092)));
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of(
            TestExecution.passed("RoundTrip#a")));
        RunContext context = RunContext.commonsRun(root, "aws-crypto-tools-commons");
        TestServerOrchestrator orchestrator = new TestServerOrchestrator(set, context,
            FakeMaterializer.succeedingUnder(root, set),
            LauncherFactory.uniform(launcher), runner,
            new DuplicateTestsDetector(), root, "python");

        orchestrator.run();

        assertTrue(runner.wasInvoked());
        assertEquals("python", runner.lastInput().referenceImplementation());
    }

    @Test
    @DisplayName("failed executed Tests report failure identifying the failed Test (Req 2.10, 10.5)")
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

    /** A structurally complete entry with an inline Feature_Declaration. */
    private static ConfigurationEntry inlineDeclarationEntry(String language, int port,
            List<String> supported, List<String> paddingSchemes) {
        return new ConfigurationEntry(language, 1, port,
            new RepositoryCoordinates("aws-crypto-tools-" + language,
                "git@github.com:aws/aws-crypto-tools-" + language + ".git", "main", "esdk"),
            new ServerLocation("aws-crypto-tools-" + language,
                "git@github.com:aws/aws-crypto-tools-" + language + ".git", "main",
                "dbesdk/test-server/server"),
            supported, List.of(), paddingSchemes, null);
    }

    @Test
    @DisplayName("declared rawRsaPaddingSchemes reach the Tests run from both carriers;"
        + " a language without the capability is absent")
    void rawRsaPaddingSchemesReachTheTestsRun(@TempDir Path root) {
        // python: inline carrier with the capability; c: cross-repo carrier (the
        // FakeMaterializer writes its declaration); java: cross-repo, no capability.
        CommonsConfiguration set = new CommonsConfiguration("esdk", List.of("raw-rsa"), List.of(
            inlineDeclarationEntry("python", 8092, List.of("raw-rsa"), List.of("PKCS1")),
            completeEntry("c", 8096),
            completeEntry("java", 8091)));
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of(
            TestExecution.passed("RoundTrip#a")));
        FakeMaterializer materializer = FakeMaterializer.succeedingUnder(root, set)
            .withRawRsaPaddingSchemes("c",
                List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"));
        RunContext context = RunContext.commonsRun(root, "aws-crypto-tools-commons");
        TestServerOrchestrator orchestrator = new TestServerOrchestrator(set, context, materializer,
            LauncherFactory.uniform(launcher), runner, new DuplicateTestsDetector(), root);

        Result result = orchestrator.run();

        // The fail-open Result reports KMS coverage-floor holes for this stub
        // run; the handoff is what this test pins: the Tests ran with both
        // carriers' capabilities.
        assertTrue(runner.wasInvoked(), () -> "the Tests must run: " + result.summary());
        assertEquals(
            Map.of("python:1:aws-crypto-tools-python", List.of("PKCS1"),
                "c:3:aws-crypto-tools-c", List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1")),
            runner.lastInput().rawRsaPaddingSchemes(),
            "both carriers' capabilities must reach the Tests run; java must be absent");
    }

    @Test
    @DisplayName("an invalid rawRsaPaddingSchemes capability aborts before any launch")
    void invalidRawRsaPaddingSchemesAborts(@TempDir Path root) {
        CommonsConfiguration set = new CommonsConfiguration("esdk", List.of("raw-rsa"), List.of(
            inlineDeclarationEntry("python", 8092, List.of("raw-rsa"),
                List.of("OAEP_SHA3_MGF1"))));
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of());
        RunContext context = RunContext.commonsRun(root, "aws-crypto-tools-commons");
        TestServerOrchestrator orchestrator = new TestServerOrchestrator(set, context,
            FakeMaterializer.succeedingUnder(root, set),
            LauncherFactory.uniform(launcher), runner,
            new DuplicateTestsDetector(), root, "python");

        Result result = orchestrator.run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("OAEP_SHA3_MGF1"),
            "the abort must name the unknown scheme: " + result.summary());
        assertEquals(0, launcher.launchCount(), "no server may launch on an invalid capability");
        assertFalse(runner.wasInvoked(), "no Tests may run on an invalid capability");
    }

    private static void writeTestsMarker(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("settings.gradle.kts"),
            "rootProject.name = \"" + DuplicateTestsDetector.testsRootNameForProduct("esdk") + "\"\n");
    }
}
