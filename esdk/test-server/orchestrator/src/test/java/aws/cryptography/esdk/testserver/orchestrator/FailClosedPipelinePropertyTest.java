package aws.cryptography.esdk.testserver.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.esdk.testserver.orchestrator.config.ServerLocation;
import aws.cryptography.esdk.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.esdk.testserver.orchestrator.record.ResolutionRecord;
import aws.cryptography.esdk.testserver.orchestrator.report.Result;
import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunner;
import aws.cryptography.esdk.testserver.orchestrator.source.ComponentId;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.esdk.testserver.orchestrator.source.Materializer;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedComponentPlan;
import aws.cryptography.esdk.testserver.orchestrator.source.RunContext;
import aws.cryptography.esdk.testserver.orchestrator.source.SourcePlan;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.constraints.IntRange;

/**
 * Property-based test for the fail-closed pipeline: drives {@link ESDKTestServer}
 * with fake Materializer/Launcher/TestRunner, injecting exactly one failure at a
 * generated stage (or none). Every failing scenario must invoke the test runner
 * zero times and report a failure naming the affected language and cause; every
 * proceeding scenario must emit the Resolution_Record before the runner is
 * invoked and before the result is reported (observed through the record's JSON
 * emission target, the pipeline's ordering seam). The fakes keep every stage
 * deterministic and in-process — no git, sockets, or subprocesses.
 */
class FailClosedPipelinePropertyTest {

    private static final List<String> LANG_POOL =
        List.of("java", "python", "rust", "go", "dotnet");

    private static final String COMMONS_REPOSITORY = "aws-crypto-tools-commons";

    /** Exactly one injected failure per scenario (or none). */
    enum FailureKind {
        /** No failure: the pipeline proceeds to the test runner. */
        NONE,
        /** Stage 1a: a Configuration_Entry with an out-of-range port. */
        INVALID_ENTRY_PORT,
        /** Stage 1a: the Configuration_Set omits the Feature_Catalog. */
        CATALOG_OMITTED,
        /** Stage 1a: the Configuration_Set omits the product. */
        PRODUCT_OMITTED,
        /** Stage 1c: an inline declaration names a Feature the catalog does not define. */
        INLINE_DECLARATION_UNKNOWN_FEATURE,
        /** Stage 1c: an inline declaration leaves a catalog Feature undeclared. */
        INLINE_DECLARATION_UNDECLARED_FEATURE,
        /** Stage 3: a cross-repo language's commons-configuration file is missing. */
        COMMONS_CONFIGURATION_MISSING,
        /** Stage 3: a cross-repo language's commons-configuration file is unparseable. */
        COMMONS_CONFIGURATION_UNPARSEABLE,
        /** Stage 3: a cross-repo commons-configuration product mismatches. */
        COMMONS_CONFIGURATION_PRODUCT_MISMATCH,
        /** Stage 2 gate: one component fails to materialize. */
        MATERIALIZATION_FAILURE,
        /** Stage 4 gate: one component is missing from the Resolution_Record. */
        RECORD_COMPONENT_DROPPED,
        /** Stage 5: one language's launch fails in a generated category. */
        LAUNCH_FAILURE
    }

    // Feature: test-server-factoring, Property 6: The pipeline is fail-closed — no failure runs any Test
    //
    // When any stage fails, the orchestrator invokes the test runner zero times
    // and reports a failure identifying the affected language (where one
    // applies) and the cause; when a run proceeds, the Resolution_Record is
    // emitted before the runner is invoked and before the result is reported.
    @Property(tries = 200)
    void thePipelineIsFailClosed(
            @ForAll("languageSubsets") List<String> langs,
            @ForAll("catalogs") List<String> catalog,
            @ForAll("failureKinds") FailureKind kind,
            @ForAll @IntRange(min = 0, max = 4) int targetSeed,
            @ForAll @IntRange(min = 0, max = 15) int inlineMask,
            @ForAll ServerLaunchException.Category launchCategory,
            @ForAll boolean injectAtServerComponent) throws IOException {

        String target = langs.get(Math.floorMod(targetSeed, langs.size()));
        Path root = Files.createTempDirectory("fail-closed-pipeline");
        try {
            // --- Arrange: the Configuration_Set, with the single injected
            // configuration-level failure where the kind demands one ---------
            ConfigurationSet set = configurationSet(langs, catalog, kind, target, inlineMask);
            RunContext context = RunContext.commonsRun(root, COMMONS_REPOSITORY);

            // The component the materialization-level injections target.
            ComponentId injected = injectAtServerComponent
                ? ComponentId.server(target) : ComponentId.library(target);
            String materializationCause = "injected: could not obtain " + injected;

            ScriptedMaterializer materializer = new ScriptedMaterializer(
                root, set.product(), catalog,
                kind == FailureKind.MATERIALIZATION_FAILURE ? injected : null,
                materializationCause,
                kind == FailureKind.RECORD_COMPONENT_DROPPED ? injected : null,
                commonsConfigurationMode(kind), target);

            LauncherFactory launcherFactory;
            if (kind == FailureKind.LAUNCH_FAILURE) {
                Map<String, Launcher> byLanguage = new LinkedHashMap<>();
                for (String lang : langs) {
                    byLanguage.put(lang, lang.equals(target)
                        ? FakeLauncher.throwing(new ServerLaunchException(
                            target, launchCategory,
                            "injected " + launchCategory + " launch failure"))
                        : FakeLauncher.succeeding());
                }
                launcherFactory = LauncherFactory.fromMap(byLanguage);
            } else {
                launcherFactory = LauncherFactory.uniform(FakeLauncher.succeeding());
            }

            Path recordJson = root.resolve(ResolutionRecord.DEFAULT_JSON_OUTPUT);
            RecordObservingRunner runner = new RecordObservingRunner(recordJson);

            ESDKTestServer orchestrator = new ESDKTestServer(set, context, materializer,
                launcherFactory, runner, new DuplicateTestsDetector(), root,
                // The generated languages need not include the default
                // reference; any configured language works for this property.
                set.entries().get(0).language());

            // --- Act ---------------------------------------------------------
            Result result = orchestrator.run();

            // --- Assert ------------------------------------------------------
            if (kind == FailureKind.NONE) {
                // A proceeding run emits the Resolution_Record before invoking
                // the test runner ...
                assertEquals(1, runner.invocations(),
                    "a no-failure run must invoke the test runner exactly once");
                assertTrue(runner.recordExistedAtEveryInvocation(),
                    "the Resolution_Record must be emitted before the test runner"
                    + " is invoked (Requirement 5.6)");
                // ... and before the result is reported: the record exists by
                // the time run() returns the reported result.
                assertTrue(Files.exists(recordJson),
                    "the Resolution_Record must be emitted before the result is"
                    + " reported (Requirement 5.6)");
            } else {
                // No failure runs any Test: zero test-runner invocations, and a
                // failure result naming the language (where one applies) and
                // the cause.
                assertEquals(0, runner.invocations(),
                    kind + ": a failing pipeline must invoke the test runner zero"
                    + " times (no partial results)");
                assertFalse(result.succeeded(),
                    kind + ": a failing pipeline must report a failed result");
                String report = result.summary() + " || " + String.join(" | ", result.details());
                String naming = expectedNaming(kind, target, injected);
                if (naming != null) {
                    assertTrue(report.contains(naming),
                        kind + ": the failure must identify the affected language"
                        + " — expected \"" + naming + "\" in: " + report);
                }
                String cause = expectedCause(kind, launchCategory, materializationCause);
                assertTrue(report.contains(cause),
                    kind + ": the failure must identify the cause — expected \""
                    + cause + "\" in: " + report);
            }
        } finally {
            deleteRecursively(root);
        }
    }

    // ------------------------------------------------------------------
    // Scenario construction
    // ------------------------------------------------------------------

    /**
     * A structurally valid Configuration_Set over {@code langs} with exactly
     * the {@code kind}'s configuration-level failure injected at the
     * {@code target} language. Languages flagged inline by {@code inlineMask}
     * carry their Feature_Declaration in their entry and name the commons
     * repository; the rest are cross-repository (declaration read from the
     * materialized commons-configuration file in stage 3). The target's carrier
     * is forced to match the kind's needs.
     */
    private static ConfigurationSet configurationSet(
            List<String> langs, List<String> catalog, FailureKind kind,
            String target, int inlineMask) {
        List<ConfigurationEntry> entries = new ArrayList<>();
        for (int i = 0; i < langs.size(); i++) {
            String lang = langs.get(i);
            boolean isTarget = lang.equals(target);
            boolean inline = (inlineMask >> i & 1) == 1;
            if (isTarget) {
                inline = switch (kind) {
                    case INLINE_DECLARATION_UNKNOWN_FEATURE,
                         INLINE_DECLARATION_UNDECLARED_FEATURE -> true;
                    case COMMONS_CONFIGURATION_MISSING,
                         COMMONS_CONFIGURATION_UNPARSEABLE,
                         COMMONS_CONFIGURATION_PRODUCT_MISMATCH -> false;
                    default -> inline;
                };
            }

            int port = isTarget && kind == FailureKind.INVALID_ENTRY_PORT
                ? ConfigurationSet.MAX_PORT + 4465 : 8000 + i;

            List<String> supported = null;
            List<String> unsupported = null;
            if (inline) {
                supported = new ArrayList<>(catalog);
                unsupported = List.of();
                if (isTarget && kind == FailureKind.INLINE_DECLARATION_UNKNOWN_FEATURE) {
                    supported.add("no-such-feature");
                }
                if (isTarget && kind == FailureKind.INLINE_DECLARATION_UNDECLARED_FEATURE) {
                    supported.remove(0);
                }
            }

            ServerLocation location = inline
                ? new ServerLocation(COMMONS_REPOSITORY,
                    "git@github.com:aws/aws-crypto-tools-commons.git", "main",
                    "esdk/test-server/servers/" + lang)
                : new ServerLocation("lang-repo-" + lang,
                    "git@github.com:aws/lang-repo-" + lang + ".git", "main",
                    "esdk/test-server/server");

            entries.add(new ConfigurationEntry(lang, 1, port,
                new RepositoryCoordinates("lib-" + lang,
                    "git@github.com:aws/lib-" + lang + ".git", "main", "."),
                location, supported, unsupported));
        }
        String product = kind == FailureKind.PRODUCT_OMITTED ? null : "esdk";
        List<String> features = kind == FailureKind.CATALOG_OMITTED ? null : catalog;
        return new ConfigurationSet(product, features, entries);
    }

    private static ScriptedMaterializer.ConfigMode commonsConfigurationMode(FailureKind kind) {
        return switch (kind) {
            case COMMONS_CONFIGURATION_MISSING -> ScriptedMaterializer.ConfigMode.ABSENT;
            case COMMONS_CONFIGURATION_UNPARSEABLE -> ScriptedMaterializer.ConfigMode.UNPARSEABLE;
            case COMMONS_CONFIGURATION_PRODUCT_MISMATCH ->
                ScriptedMaterializer.ConfigMode.WRONG_PRODUCT;
            default -> ScriptedMaterializer.ConfigMode.VALID;
        };
    }

    // ------------------------------------------------------------------
    // Expected report contents per injected failure
    // ------------------------------------------------------------------

    /**
     * The token naming the affected language in the failure report, or
     * {@code null} where no language applies (a Configuration_Set-level
     * omission names the Configuration_Set, not a language).
     */
    private static String expectedNaming(FailureKind kind, String target, ComponentId injected) {
        return switch (kind) {
            case NONE -> null;
            case INVALID_ENTRY_PORT -> "entry " + target;
            case CATALOG_OMITTED, PRODUCT_OMITTED -> "Configuration_Set";
            case INLINE_DECLARATION_UNKNOWN_FEATURE,
                 INLINE_DECLARATION_UNDECLARED_FEATURE,
                 COMMONS_CONFIGURATION_MISSING,
                 COMMONS_CONFIGURATION_UNPARSEABLE -> "language " + target;
            case COMMONS_CONFIGURATION_PRODUCT_MISMATCH ->
                "Language_Repository lang-repo-" + target;
            case MATERIALIZATION_FAILURE, RECORD_COMPONENT_DROPPED -> injected.toString();
            case LAUNCH_FAILURE -> "failed to launch the " + target;
        };
    }

    /** The token identifying the failure cause in the report. */
    private static String expectedCause(
            FailureKind kind, ServerLaunchException.Category category,
            String materializationCause) {
        return switch (kind) {
            case NONE -> "";
            case INVALID_ENTRY_PORT -> "out of range";
            case CATALOG_OMITTED -> "missing Feature_Catalog";
            case PRODUCT_OMITTED -> "missing product";
            case INLINE_DECLARATION_UNKNOWN_FEATURE -> "unknown Feature";
            case INLINE_DECLARATION_UNDECLARED_FEATURE -> "undeclared";
            case COMMONS_CONFIGURATION_MISSING, COMMONS_CONFIGURATION_UNPARSEABLE ->
                "missing or unparseable; expected location: ";
            case COMMONS_CONFIGURATION_PRODUCT_MISMATCH ->
                "does not match the Configuration_Set product";
            case MATERIALIZATION_FAILURE -> materializationCause;
            case RECORD_COMPONENT_DROPPED -> "Resolution_Record is incomplete";
            case LAUNCH_FAILURE -> "[" + category + "]";
        };
    }

    // ------------------------------------------------------------------
    // Generators
    // ------------------------------------------------------------------

    @Provide
    Arbitrary<List<String>> languageSubsets() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(1).ofMaxSize(4).map(List::copyOf);
    }

    @Provide
    Arbitrary<List<String>> catalogs() {
        return Arbitraries.subsetOf("streaming", "MPL", "keyring")
            .ofMinSize(1).map(List::copyOf);
    }

    /**
     * The injected failure kind — {@link FailureKind#NONE} weighted up so both
     * halves of the property (fail-closed aborts and proceeding-run ordering)
     * are exercised well within the try budget.
     */
    @Provide
    Arbitrary<FailureKind> failureKinds() {
        List<Tuple.Tuple2<Integer, FailureKind>> frequencies = new ArrayList<>();
        for (FailureKind kind : FailureKind.values()) {
            frequencies.add(Tuple.of(kind == FailureKind.NONE ? 4 : 1, kind));
        }
        return Arbitraries.frequency(frequencies.toArray(Tuple.Tuple2[]::new));
    }

    // ------------------------------------------------------------------
    // Test doubles
    // ------------------------------------------------------------------

    /**
     * A {@link TestRunner} that observes the pipeline's ordering seam: at every
     * invocation it records whether the Resolution_Record's JSON emission
     * target already exists (it must be emitted before the runner is invoked)
     * and counts invocations so failing scenarios can assert the runner ran
     * zero times.
     */
    private static final class RecordObservingRunner implements TestRunner {

        private final Path recordJson;
        private int invocations = 0;
        private boolean recordExistedAtEveryInvocation = true;

        RecordObservingRunner(Path recordJson) {
            this.recordJson = recordJson;
        }

        int invocations() {
            return invocations;
        }

        boolean recordExistedAtEveryInvocation() {
            return recordExistedAtEveryInvocation;
        }

        @Override
        public List<TestExecution> run(TestRunInput input) throws MissingRuntimeConfigException {
            invocations++;
            recordExistedAtEveryInvocation &= Files.exists(recordJson);
            return List.of(TestExecution.passed("FailClosedPipelinePropertyTest#observed"));
        }
    }

    /**
     * A scriptable {@link Materializer} (modeled on {@link FakeMaterializer}):
     * every plan materializes successfully, except an optional single injected
     * {@code failComponent} (returned as a {@link MaterializedSources.Failure})
     * or a single {@code dropComponent} (omitted entirely, making the
     * Resolution_Record incomplete). For every server component it writes a
     * commons-configuration file under the resolved root so stage-3
     * cross-repository Feature validation finds one; the {@code targetLanguage}
     * server's file is written per the scenario's {@link ConfigMode}.
     */
    private static final class ScriptedMaterializer implements Materializer {

        enum ConfigMode { VALID, ABSENT, UNPARSEABLE, WRONG_PRODUCT }

        private final Path root;
        private final String product;
        private final List<String> catalog;
        private final ComponentId failComponent;
        private final String failCause;
        private final ComponentId dropComponent;
        private final ConfigMode targetConfigMode;
        private final String targetLanguage;

        ScriptedMaterializer(Path root, String product, List<String> catalog,
                ComponentId failComponent, String failCause, ComponentId dropComponent,
                ConfigMode targetConfigMode, String targetLanguage) {
            this.root = root;
            this.product = product;
            this.catalog = catalog;
            this.failComponent = failComponent;
            this.failCause = failCause;
            this.dropComponent = dropComponent;
            this.targetConfigMode = targetConfigMode;
            this.targetLanguage = targetLanguage;
        }

        @Override
        public MaterializedSources materialize(List<ResolvedComponentPlan> plans) {
            List<MaterializedSources.Outcome> outcomes = new ArrayList<>(plans.size());
            for (ResolvedComponentPlan plan : plans) {
                if (plan.component().equals(dropComponent)) {
                    continue; // omitted entirely: the record cannot be complete
                }
                if (plan.component().equals(failComponent)) {
                    outcomes.add(new MaterializedSources.Failure(
                        plan.component(), plan.plan(), plan.reason(), failCause));
                    continue;
                }
                boolean workingTree = plan.plan() instanceof SourcePlan.WorkingTree;
                MaterializedSources.Success success = new MaterializedSources.Success(
                    plan.component(), plan.plan(), plan.reason(),
                    root.resolve(plan.component().toString().replace(':', '-')),
                    "0000000000000000000000000000000000000000",
                    "fake-ref",
                    workingTree ? Boolean.FALSE : null);
                if (plan.component().kind() == ComponentId.Kind.SERVER) {
                    ConfigMode mode = plan.component().language().equals(targetLanguage)
                        ? targetConfigMode : ConfigMode.VALID;
                    writeCommonsConfiguration(success.root(), mode);
                }
                outcomes.add(success);
            }
            return new MaterializedSources(outcomes);
        }

        private void writeCommonsConfiguration(Path serverRoot, ConfigMode mode) {
            if (mode == ConfigMode.ABSENT) {
                return;
            }
            Path file = serverRoot.resolve(ESDKTestServer.COMMONS_CONFIGURATION_RELATIVE_PATH);
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, switch (mode) {
                    case UNPARSEABLE -> "{ this is not JSON";
                    case WRONG_PRODUCT -> commonsConfigurationJson(product + "-mismatched");
                    default -> commonsConfigurationJson(product);
                });
            } catch (IOException e) {
                throw new UncheckedIOException(
                    "scripted materializer could not write " + file, e);
            }
        }

        private String commonsConfigurationJson(String productValue) {
            StringJoiner supported = new StringJoiner(", ", "[", "]");
            for (String feature : catalog) {
                supported.add('"' + feature + '"');
            }
            return "{\n"
                + "  \"commonsRepository\": {\n"
                + "    \"name\": \"aws-crypto-tools-commons\",\n"
                + "    \"url\": \"git@github.com:aws/aws-crypto-tools-commons.git\",\n"
                + "    \"branch\": \"main\"\n"
                + "  },\n"
                + "  \"product\": \"" + productValue + "\",\n"
                + "  \"supportedFeatures\": " + supported + ",\n"
                + "  \"unsupportedFeatures\": []\n"
                + "}\n";
        }
    }

    // ------------------------------------------------------------------
    // Housekeeping
    // ------------------------------------------------------------------

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException ignored) {
                    // Best-effort cleanup of the per-try scratch directory.
                }
            });
        }
    }
}
