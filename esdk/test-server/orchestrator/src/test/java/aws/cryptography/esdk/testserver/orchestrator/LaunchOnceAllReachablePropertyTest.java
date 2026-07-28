package aws.cryptography.esdk.testserver.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.esdk.testserver.orchestrator.config.ServerLocation;
import aws.cryptography.esdk.testserver.orchestrator.launch.CloseResult;
import aws.cryptography.esdk.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunner;
import aws.cryptography.esdk.testserver.orchestrator.run.TestTarget;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.esdk.testserver.orchestrator.source.RunContext;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

// Feature: test-server-factoring, Property 7: Every entry launches once, and Tests start only after all are reachable

/**
 * Property 7 (design "Correctness Properties"): for any generated valid
 * {@code Configuration_Set}, the orchestrated pipeline
 * <ul>
 *   <li>invokes the launcher exactly once per {@code Configuration_Entry},
 *       with that entry's configured port (Requirement 2.1);</li>
 *   <li>invokes the test runner only after every launched server has
 *       reported reachable (Requirements 2.2, 2.3);</li>
 *   <li>hands the runner exactly the launched
 *       {@code (language, majorVersion, endpoint)} set as its Targets
 *       (Requirement 2.2).</li>
 * </ul>
 *
 * <p>The pipeline is driven hermetically: {@link FakeMaterializer} stands in
 * for git, an instrumented launcher records each {@code (language, port)}
 * launch and marks its server reachable only on return, and a recording
 * runner snapshots — at the instant it is invoked — how many servers had
 * launched and whether each had reported reachable. Every generated entry
 * carries an inline Feature_Declaration partitioning the whole catalog, so
 * stage-1 validation covers all declarations and no cross-repository
 * declaration loading is triggered.
 *
 * <p><b>Validates: Requirements 2.1, 2.2, 2.3</b>
 */
class LaunchOnceAllReachablePropertyTest {

    private static final String INVOKING_REPOSITORY = "aws-crypto-tools-commons";

    @Property(tries = 100)
    void everyEntryLaunchesOnceAndTestsStartOnlyAfterAllReachable(
            @ForAll("validConfigurationSets") ConfigurationSet set) throws IOException {
        Path root = Files.createTempDirectory("p7-launch-once");
        try {
            RecordingLauncher launcher = new RecordingLauncher();
            RecordingTestRunner runner = new RecordingTestRunner(launcher);
            RunContext context = RunContext.commonsRun(root, INVOKING_REPOSITORY);
            ESDKTestServer orchestrator = new ESDKTestServer(set, context,
                FakeMaterializer.succeedingUnder(root, set),
                LauncherFactory.uniform(launcher), runner,
                new DuplicateTestsDetector(), root);

            orchestrator.run();

            List<ConfigurationEntry> entries = set.entries();

            // Exactly one launch per Configuration_Entry, at that entry's
            // configured port (Requirement 2.1).
            assertEquals(entries.size(), launcher.launches.size(),
                "expected exactly one launch per Configuration_Entry");
            for (ConfigurationEntry entry : entries) {
                List<RecordingLauncher.Launch> forLanguage = launcher.launches.stream()
                    .filter(l -> l.language().equals(entry.language()))
                    .toList();
                assertEquals(1, forLanguage.size(),
                    "language '" + entry.language() + "' must launch exactly once");
                assertEquals(entry.port().intValue(), forLanguage.get(0).port(),
                    "language '" + entry.language()
                        + "' must launch at its configured port");
            }

            // The runner was invoked exactly once, and only after every
            // configured server had launched and reported reachable
            // (Requirements 2.2, 2.3).
            assertEquals(1, runner.invocationCount, "the Tests must run exactly once");
            assertEquals(entries.size(), runner.launchedCountAtInvocation,
                "every server must have launched before the Tests start");
            for (Map.Entry<String, Boolean> reachable
                    : runner.reachableAtInvocation.entrySet()) {
                assertTrue(reachable.getValue(), "the '" + reachable.getKey()
                    + "' server must have reported reachable before the Tests start");
            }

            // The Targets handed to the runner are exactly the launched
            // (language, majorVersion, endpoint) set (Requirement 2.2).
            List<TestTarget> expectedTargets = new ArrayList<>();
            for (ConfigurationEntry entry : entries) {
                expectedTargets.add(new TestTarget(entry.language(), entry.majorVersion(),
                    URI.create("http://127.0.0.1:" + entry.port())));
            }
            assertEquals(expectedTargets, runner.input.targets(),
                "the runner's Targets must be exactly the launched set");
        } finally {
            deleteRecursively(root);
        }
    }

    // ------------------------------------------------------------------
    // Generators
    // ------------------------------------------------------------------

    /**
     * Valid Configuration_Sets: a non-blank product, a duplicate-free
     * Feature_Catalog (0..3 names), and 1..5 entries with unique languages,
     * unique in-range ports, majorVersion >= 1, complete libraryRepository
     * and serverLocation coordinates, and an inline Feature_Declaration
     * partitioning the whole catalog between supported and unsupported.
     */
    @Provide
    Arbitrary<ConfigurationSet> validConfigurationSets() {
        Arbitrary<String> shortName = Arbitraries.strings()
            .withCharRange('a', 'z').ofMinLength(1).ofMaxLength(8);
        Arbitrary<List<String>> catalogs =
            shortName.list().uniqueElements().ofMaxSize(3);
        Arbitrary<List<String>> languageLists =
            shortName.list().uniqueElements().ofMinSize(1).ofMaxSize(5);

        return Combinators.combine(shortName, catalogs, languageLists)
            .flatAs((product, catalog, languages) -> {
                int n = languages.size();
                Arbitrary<List<Integer>> ports = Arbitraries.integers()
                    .between(ConfigurationSet.MIN_PORT, ConfigurationSet.MAX_PORT)
                    .list().uniqueElements().ofSize(n);
                Arbitrary<List<Integer>> majorVersions = Arbitraries.integers()
                    .between(1, 99).list().ofSize(n);
                // One supported/unsupported partition mask of the catalog per
                // language: true = supported, false = unsupported.
                Arbitrary<List<List<Boolean>>> masks = Arbitraries.of(true, false)
                    .list().ofSize(catalog.size()).list().ofSize(n);
                return Combinators.combine(ports, majorVersions, masks)
                    .as((portList, majorList, maskList) -> {
                        List<ConfigurationEntry> entries = new ArrayList<>(n);
                        for (int i = 0; i < n; i++) {
                            entries.add(entry(languages.get(i), majorList.get(i),
                                portList.get(i), catalog, maskList.get(i)));
                        }
                        return new ConfigurationSet(product, catalog, entries);
                    });
            });
    }

    private static ConfigurationEntry entry(String language, int majorVersion, int port,
            List<String> catalog, List<Boolean> supportedMask) {
        List<String> supported = new ArrayList<>();
        List<String> unsupported = new ArrayList<>();
        for (int f = 0; f < catalog.size(); f++) {
            (supportedMask.get(f) ? supported : unsupported).add(catalog.get(f));
        }
        return new ConfigurationEntry(language, majorVersion, port,
            new RepositoryCoordinates("lib-" + language,
                "git@example.invalid:lib-" + language + ".git", "main", "."),
            new ServerLocation("server-repo-" + language,
                "git@example.invalid:server-" + language + ".git", "main",
                "servers/" + language),
            supported, unsupported);
    }

    // ------------------------------------------------------------------
    // Instrumented test doubles (local to this property; the shared
    // FakeLauncher/StubTestRunner doubles are final and stay untouched)
    // ------------------------------------------------------------------

    /**
     * A {@link Launcher} that records each {@code (language, port)} launch
     * invocation and marks the launched server reachable only when
     * {@code launch()} returns — so a runner invoked before a launch
     * completed would observe an unreachable server.
     */
    private static final class RecordingLauncher implements Launcher {

        record Launch(String language, int port) {
        }

        final List<Launch> launches = new ArrayList<>();
        final Map<String, AtomicBoolean> reachableByLanguage = new LinkedHashMap<>();

        @Override
        public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources) {
            launches.add(new Launch(entry.language(), entry.port()));
            AtomicBoolean reachable = new AtomicBoolean(false);
            reachableByLanguage.put(entry.language(), reachable);
            LaunchedServer server = new LaunchedServer(entry.language(), entry.port(),
                URI.create("http://127.0.0.1:" + entry.port()),
                CloseResult::stopped, reachable::get);
            // Reachability is reported only on launch() return; no real port
            // is bound (the pipeline's re-check reads this flag, not TCP).
            reachable.set(true);
            return server;
        }
    }

    /**
     * A {@link TestRunner} that snapshots, at the instant it is invoked, how
     * many servers had launched and whether each had reported reachable, and
     * keeps the {@link TestRunInput} it was handed.
     */
    private static final class RecordingTestRunner implements TestRunner {

        private final RecordingLauncher launcher;
        int invocationCount = 0;
        int launchedCountAtInvocation = -1;
        final Map<String, Boolean> reachableAtInvocation = new LinkedHashMap<>();
        TestRunInput input;

        RecordingTestRunner(RecordingLauncher launcher) {
            this.launcher = launcher;
        }

        @Override
        public List<TestExecution> run(TestRunInput runInput) {
            invocationCount++;
            launchedCountAtInvocation = launcher.launches.size();
            launcher.reachableByLanguage.forEach(
                (language, flag) -> reachableAtInvocation.put(language, flag.get()));
            this.input = runInput;
            return List.of(TestExecution.passed("Property7#launchOnce"));
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
                } catch (IOException ignored) {
                    // best-effort temp cleanup
                }
            });
        }
    }
}
