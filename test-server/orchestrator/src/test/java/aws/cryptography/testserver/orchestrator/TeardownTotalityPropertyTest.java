package aws.cryptography.testserver.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.testserver.orchestrator.config.ServerLocation;
import aws.cryptography.testserver.orchestrator.launch.CloseResult;
import aws.cryptography.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.testserver.orchestrator.launch.Launcher;
import aws.cryptography.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.testserver.orchestrator.report.Result;
import aws.cryptography.testserver.orchestrator.report.ResultReporter;
import aws.cryptography.testserver.orchestrator.report.TestExecution;
import aws.cryptography.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.testserver.orchestrator.run.TestRunner;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.RunContext;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for the orchestrated pipeline's teardown totality
 * (design Property 8): for any generated run outcome — success, test failure,
 * or abort after any subset of servers launched — and any generated subset of
 * servers that fail to stop, stop is invoked on every server that was launched
 * regardless of outcome, and the run report contains a cleanup failure naming
 * exactly the languages whose servers did not stop.
 *
 * <p>The pipeline runs against instrumented fakes: {@link LaunchedServer}s
 * whose terminators count their invocations and return a generated
 * {@link CloseResult} (STOPPED or STILL_RUNNING), a launcher that optionally
 * throws on the (K+1)th launch, and a runner that returns passing/failing
 * executions or refuses — no git, sockets, or subprocesses.
 */
class TeardownTotalityPropertyTest {

    // Feature: test-server-factoring, Property 8: Teardown is total and cleanup failures are named
    @Property(tries = 200)
    void teardownIsTotalAndCleanupFailuresAreNamed(@ForAll("scenarios") Scenario scenario)
            throws IOException {
        List<String> languages = scenario.languages();
        List<String> expectedLaunched = scenario.outcome().kind() == Kind.LAUNCH_FAILURE
            ? languages.stream()
                .filter(language -> !language.equals(scenario.outcome().failLanguage()))
                .toList()
            : languages;
        Set<String> expectedStillRunning = new LinkedHashSet<>();
        for (String language : expectedLaunched) {
            if (scenario.stillRunning().contains(language)) {
                expectedStillRunning.add(language);
            }
        }

        ConfigurationSet set = configurationSet(languages);
        RecordingLauncher launcher = new RecordingLauncher(
            scenario.outcome().kind() == Kind.LAUNCH_FAILURE
                ? scenario.outcome().failLanguage() : null,
            scenario.stillRunning());
        StubTestRunner runner = runnerFor(scenario.outcome(), languages);

        Path root = Files.createTempDirectory("teardown-pbt");
        Result result;
        try {
            RunContext context = RunContext.commonsRun(root, "aws-crypto-tools-commons");
            TestServerOrchestrator orchestrator = new TestServerOrchestrator(set, context,
                FakeMaterializer.succeedingUnder(root, set),
                LauncherFactory.uniform(launcher), runner,
                new DuplicateTestsDetector(), root,
                // The generated languages need not include the default
                // reference; any configured language works for this property.
                set.entries().get(0).language());
            result = orchestrator.run();
        } finally {
            deleteRecursively(root);
        }

        // The generated outcome actually happened: the expected prefix launched,
        // and the runner ran only on the non-abort paths.
        assertEquals(Set.copyOf(expectedLaunched), Set.copyOf(launcher.launchedLanguages()),
            "exactly the servers whose launch did not fail must have launched");
        assertEquals(scenario.outcome().kind() != Kind.LAUNCH_FAILURE, runner.wasInvoked(),
            "the runner runs exactly when every launch succeeded");
        assertEquals(scenario.outcome().kind() == Kind.ALL_PASS, result.succeeded(),
            () -> "the primary result must reflect the generated outcome "
                + scenario.outcome().kind() + ": " + result);

        // Teardown is total: stop was invoked on every server that was
        // launched, whatever the outcome. close() is idempotent and the
        // orchestrator closes each launched server once, so each instrumented
        // terminator fires exactly once — and in particular at least once.
        for (InstrumentedServer server : launcher.launched()) {
            assertEquals(1, server.stopInvocations(),
                () -> "stop must be invoked on the launched " + server.language()
                    + " server regardless of outcome " + scenario.outcome().kind());
        }

        // The report names exactly the still-running languages: one
        // cleanup-failure detail per generated stop failure among the launched
        // servers — no more, no fewer — whether the primary result passed,
        // failed, or aborted.
        List<String> reported = cleanupFailureLanguages(result);
        assertEquals(new LinkedHashSet<>(reported).size(), reported.size(),
            () -> "cleanup failures must not repeat a language: " + reported);
        assertEquals(expectedStillRunning, new LinkedHashSet<>(reported),
            () -> "the report must name exactly the still-running languages: " + result);
        if (!expectedStillRunning.isEmpty()) {
            for (String language : expectedStillRunning) {
                assertTrue(result.summary().contains(language),
                    () -> "the summary must name still-running language "
                        + language + ": " + result.summary());
            }
        } else {
            assertFalse(result.summary().contains("cleanup failure"),
                () -> "no cleanup failure may be reported when every server stopped: "
                    + result.summary());
        }
    }

    // ------------------------------------------------------------------
    // Generators
    // ------------------------------------------------------------------

    /** The generated run outcome kinds of design Property 8. */
    private enum Kind { ALL_PASS, TEST_FAILS, LAUNCH_FAILURE, RUNNER_EXCEPTION }

    /**
     * A generated run outcome; {@code failLanguage} is the language whose launch
     * fails (LAUNCH_FAILURE only, else {@code null}).
     */
    private record RunOutcome(Kind kind, String failLanguage) { }

    /** A generated multi-language run with a stop-failure subset. */
    private record Scenario(List<String> languages, RunOutcome outcome, Set<String> stillRunning) { }

    @Provide
    Arbitrary<Scenario> scenarios() {
        Arbitrary<List<String>> languages = Arbitraries
            .of("java", "python", "rust", "go", "dotnet")
            .set().ofMinSize(1).ofMaxSize(4)
            .map(s -> List.copyOf(new ArrayList<>(s)));
        return languages.flatMap(langs ->
            Combinators.combine(outcomes(langs), Arbitraries.subsetOf(langs))
                .as((outcome, still) -> new Scenario(langs, outcome, still)));
    }

    /** All four outcome kinds; a launch failure of any one of the servers. */
    private static Arbitrary<RunOutcome> outcomes(List<String> languages) {
        return Arbitraries.oneOf(
            Arbitraries.of(Kind.ALL_PASS, Kind.TEST_FAILS, Kind.RUNNER_EXCEPTION)
                .map(kind -> new RunOutcome(kind, null)),
            Arbitraries.of(languages.toArray(new String[0]))
                .map(language -> new RunOutcome(Kind.LAUNCH_FAILURE, language)));
    }

    // ------------------------------------------------------------------
    // Pipeline inputs
    // ------------------------------------------------------------------

    /**
     * A structurally valid Configuration_Set over {@code languages}: unique
     * ports, complete library/server coordinates, and a catalog-complete inline
     * Feature_Declaration per entry so stage-1 validation passes as-is.
     */
    private static ConfigurationSet configurationSet(List<String> languages) {
        List<String> catalog = List.of("streaming", "MPL");
        List<ConfigurationEntry> entries = new ArrayList<>();
        for (int i = 0; i < languages.size(); i++) {
            String language = languages.get(i);
            entries.add(new ConfigurationEntry(language, 3, 8100 + i,
                new RepositoryCoordinates("repo-" + language,
                    "git@github.com:aws/repo-" + language + ".git", "main", "."),
                new ServerLocation("repo-" + language,
                    "git@github.com:aws/repo-" + language + ".git", "main",
                    "esdk/test-server/server"),
                catalog, List.of()));
        }
        return new ConfigurationSet("esdk", catalog, entries);
    }

    /** The runner realizing the generated outcome (labels are {@code <lang>-v3}). */
    private static StubTestRunner runnerFor(RunOutcome outcome, List<String> languages) {
        return switch (outcome.kind()) {
            case RUNNER_EXCEPTION -> StubTestRunner.refusing();
            case ALL_PASS -> StubTestRunner.returning(fullKmsCoverage(languages));
            case TEST_FAILS -> {
                List<TestExecution> executions =
                    new ArrayList<>(fullKmsCoverage(languages));
                executions.add(TestExecution.failed(
                    "Tests#blob[rawAes] " + languages.get(0) + "-v3->"
                        + languages.get(0) + "-v3", "generated mismatch"));
                yield StubTestRunner.returning(executions);
            }
            // Never invoked on the launch-failure path; asserted via wasInvoked().
            case LAUNCH_FAILURE -> StubTestRunner.returning(List.of());
        };
    }

    /**
     * One passed execution per launched (encrypt, decrypt) pair × required KMS
     * scenario, in the Tests' stable naming, so the ALL_PASS outcome clears the
     * reporter's KMS coverage floor and is a genuine success.
     */
    private static List<TestExecution> fullKmsCoverage(List<String> languages) {
        List<TestExecution> executions = new ArrayList<>();
        for (String encrypt : languages) {
            for (String decrypt : languages) {
                for (String scenario : ResultReporter.DEFAULT_REQUIRED_KMS_SCENARIOS) {
                    executions.add(TestExecution.passed("Tests#blob[" + scenario + "] "
                        + encrypt + "-v3->" + decrypt + "-v3"));
                }
            }
        }
        return executions;
    }

    // ------------------------------------------------------------------
    // Report parsing
    // ------------------------------------------------------------------

    private static final String CLEANUP_PREFIX = "cleanup failure: the ";
    private static final String CLEANUP_SUFFIX = " Language_Server was not stopped";

    /** The languages named by the report's cleanup-failure details, in order. */
    private static List<String> cleanupFailureLanguages(Result result) {
        List<String> languages = new ArrayList<>();
        for (String detail : result.details()) {
            if (detail.startsWith(CLEANUP_PREFIX) && detail.contains(CLEANUP_SUFFIX)) {
                languages.add(detail.substring(CLEANUP_PREFIX.length(),
                    detail.indexOf(CLEANUP_SUFFIX)));
            }
        }
        return languages;
    }

    // ------------------------------------------------------------------
    // Instrumented fakes (local to this test; shared doubles are not modified)
    // ------------------------------------------------------------------

    /**
     * A launched server whose terminator counts its invocations and returns the
     * generated {@link CloseResult} — STOPPED, or STILL_RUNNING naming the
     * language.
     */
    private static final class InstrumentedServer {
        private final String language;
        private final AtomicInteger stopInvocations = new AtomicInteger();
        private final LaunchedServer server;

        InstrumentedServer(String language, int port, boolean stillRunning) {
            this.language = language;
            // An explicit always-reachable probe: no real port is bound, so the
            // pipeline's pre-Tests reachability re-check must not TCP-connect.
            this.server = new LaunchedServer(language, port,
                URI.create("http://127.0.0.1:" + port),
                () -> {
                    stopInvocations.incrementAndGet();
                    return stillRunning
                        ? CloseResult.stillRunning(language)
                        : CloseResult.stopped();
                },
                () -> true);
        }

        String language() {
            return language;
        }

        int stopInvocations() {
            return stopInvocations.get();
        }

        LaunchedServer server() {
            return server;
        }
    }

    /**
     * A {@link Launcher} that records every launch as an
     * {@link InstrumentedServer} and optionally throws on the (K+1)th launch,
     * modeling an abort after K servers launched.
     */
    private static final class RecordingLauncher implements Launcher {
        private final String failLanguage; // the language whose launch throws; null = none
        private final Set<String> stillRunningLanguages;
        private final List<InstrumentedServer> launched =
            Collections.synchronizedList(new ArrayList<>());

        RecordingLauncher(String failLanguage, Set<String> stillRunningLanguages) {
            this.failLanguage = failLanguage;
            this.stillRunningLanguages = stillRunningLanguages;
        }

        List<InstrumentedServer> launched() {
            return launched;
        }

        List<String> launchedLanguages() {
            return launched.stream().map(InstrumentedServer::language).toList();
        }

        @Override
        public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
                throws ServerLaunchException {
            if (entry.language().equals(failLanguage)) {
                throw new ServerLaunchException(entry.language(),
                    ServerLaunchException.Category.BUILD,
                    "generated launch failure for " + failLanguage);
            }
            InstrumentedServer server = new InstrumentedServer(entry.language(),
                entry.port(), stillRunningLanguages.contains(entry.language()));
            launched.add(server);
            return server.server();
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
    }
}
