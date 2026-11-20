package aws.cryptography.testserver.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.testserver.orchestrator.config.ServerLocation;
import aws.cryptography.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.testserver.orchestrator.report.Result;
import aws.cryptography.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.testserver.orchestrator.run.TestTarget;
import aws.cryptography.testserver.orchestrator.source.RunContext;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A dry run launches no server and hands the Tests one dry-run Target. */
class DryRunOrchestratorTest {

    private static ConfigurationEntry entry(String language, int port) {
        return new ConfigurationEntry(language, 1, port,
            new RepositoryCoordinates("aws-crypto-tools-" + language,
                "git@github.com:aws/aws-crypto-tools-" + language + ".git", "main", "esdk"),
            new ServerLocation("aws-crypto-tools-" + language,
                "git@github.com:aws/aws-crypto-tools-" + language + ".git", "main",
                "esdk/test-server"),
            List.of("raw-aes"), List.of("caching"), null, null);
    }

    private static final CommonsConfiguration TWO_LANGUAGES = new CommonsConfiguration(
        "esdk", List.of("raw-aes", "caching"), List.of(entry("rust", 8093), entry("java", 8091)));

    private static TestServerOrchestrator orchestrator(
            FakeLauncher launcher, StubTestRunner runner, Path root) {
        return new TestServerOrchestrator(TWO_LANGUAGES,
            RunContext.commonsRun(root, "aws-crypto-tools-commons"),
            FakeMaterializer.succeedingUnder(root, TWO_LANGUAGES),
            LauncherFactory.uniform(launcher), runner,
            new DuplicateTestsDetector(), root, "rust");
    }

    @Test
    void runsTheTestsAgainstTheDryRunEndpointWithNoServer(@TempDir Path root) {
        FakeLauncher launcher = FakeLauncher.succeeding();
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(launcher, runner, root)
            .withLanguages(Set.of("rust"))
            .withDryRun(true)
            .run();

        assertTrue(result.succeeded(), result.summary());
        assertEquals(0, launcher.launchCount(), "a dry run launches no server");
        TestRunInput input = runner.lastInput();
        assertTrue(input.dryRun());
        assertEquals(List.of(new TestTarget("rust", 1, "aws-crypto-tools-rust",
            TestServerOrchestrator.DRY_RUN_ENDPOINT)), input.targets());
        assertEquals(List.of("rust:1:aws-crypto-tools-rust"), List.copyOf(input.features().keySet()));
    }

    @Test
    void refusesMoreThanOneLanguage(@TempDir Path root) {
        StubTestRunner runner = StubTestRunner.returning(List.of());

        Result result = orchestrator(FakeLauncher.succeeding(), runner, root)
            .withDryRun(true)
            .run();

        assertFalse(result.succeeded());
        assertTrue(result.summary().contains("dryRun needs exactly one language"), result.summary());
        assertFalse(runner.wasInvoked());
    }
}
