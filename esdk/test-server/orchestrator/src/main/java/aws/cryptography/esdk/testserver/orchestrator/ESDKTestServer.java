package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationLoadException;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationLoader;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSetValidation;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationValidation;
import aws.cryptography.esdk.testserver.orchestrator.config.FeatureValidation;
import aws.cryptography.esdk.testserver.orchestrator.launch.CloseResult;
import aws.cryptography.esdk.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.esdk.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.esdk.testserver.orchestrator.record.ResolutionRecord;
import aws.cryptography.esdk.testserver.orchestrator.report.Result;
import aws.cryptography.esdk.testserver.orchestrator.report.ResultReporter;
import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunner;
import aws.cryptography.esdk.testserver.orchestrator.run.TestTarget;
import aws.cryptography.esdk.testserver.orchestrator.source.ComponentId;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.esdk.testserver.orchestrator.source.Materializer;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedComponentPlan;
import aws.cryptography.esdk.testserver.orchestrator.source.RunContext;
import aws.cryptography.esdk.testserver.orchestrator.source.SourceResolver;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * The ESDK TestServer orchestrator core — the fail-closed pipeline over the
 * {@code Configuration_Set}, the {@link RunContext}, any
 * Configuration_Overrides, and the launched {@code Language_Server}s (design
 * "The orchestrated run pipeline").
 *
 * <p>The stages, in design order — any stage 1–5 failure runs zero
 * {@code Tests}, records no partial results, and reports a fail-open failure
 * identifying the language (where one applies) and the cause:
 * <ol>
 *   <li>Load + validate the {@code Configuration_Set} and the on-hand
 *       Feature_Declarations: structural validation before anything is cloned
 *       (Requirements 3.2, 3.8, 4.7, 4.11, 7.4, 7.5), the duplicate-Tests
 *       check (Requirement 10.1), every Feature_Declaration carried inline in
 *       an effective entry, and — on a Language_Repository_Run — the own
 *       repository's commons-configuration file (declaration + product match;
 *       Requirements 8.4–8.11).</li>
 *   <li>Materialize the planned sources: pure resolution planning, then git
 *       clones / working-tree checks (Requirements 3.3–3.7, 4).</li>
 *   <li>Complete Feature validation for declarations obtained by
 *       materialization — a language whose effective entry carries no inline
 *       declaration reads it from
 *       {@code <server root>/esdk/test-server/commons-configuration.json}
 *       (e.g. Java's in a Commons_Run), including the product match
 *       (Requirements 8.4, 8.10, 8.11).</li>
 *   <li>Produce + emit the Resolution_Record — stdout block and
 *       {@code orchestrator/build/resolution-record.json} — <em>before</em>
 *       any launch, any Test, and the reported result (Requirement 5.6),
 *       failures included (Requirement 5.4); gate on completeness
 *       (Requirement 5.5), then on materialization failures
 *       (Requirement 3.6). (Emission precedes the stage-3 checks in code so
 *       the record always accompanies a materialization-failure abort.)</li>
 *   <li>Build + launch every server on its configured port
 *       (Requirements 2.1, 2.5), then re-check reachability across all
 *       launched ports — Tests start only after every server is reachable
 *       (Requirements 2.3, 2.9).</li>
 *   <li>Run the Tests with the targets / features / featureCatalog runtime
 *       properties (Requirements 2.2, 9.3, 10.2).</li>
 *   <li>Report the fail-open {@link Result} including the KMS coverage floor
 *       (Requirements 2.8, 2.10, 10.4).</li>
 *   <li>Teardown in {@code finally}, whatever the outcome (Requirement 2.6);
 *       {@code STILL_RUNNING} close results feed the report's cleanup
 *       failures without ever masking the primary result
 *       (Requirement 2.11).</li>
 * </ol>
 */
public final class ESDKTestServer {

    /**
     * The DEFAULT repository-root-relative location of a Language_Repository's
     * commons-configuration file (Commons_Configuration_Entry + {@code product}
     * + Feature_Declaration; design "Commons-configuration file"). A
     * Configuration_Entry whose Language_Repository places the file elsewhere
     * overrides this via {@code commonsConfigurationPath}.
     */
    static final String COMMONS_CONFIGURATION_RELATIVE_PATH =
        "esdk/test-server/commons-configuration.json";

    /**
     * The repository-root-relative path to {@code entry}'s commons-configuration
     * file: the entry's {@code commonsConfigurationPath} when set, otherwise
     * {@link #COMMONS_CONFIGURATION_RELATIVE_PATH}. Lets a Language_Repository
     * whose layout differs from the default (e.g. the Rust server, whose sources
     * live under {@code esdk-test-server/}) carry its declaration alongside them.
     */
    static String commonsConfigurationRelativePath(ConfigurationEntry entry) {
        String configured = entry == null ? null : entry.commonsConfigurationPath();
        return configured == null || configured.isBlank()
            ? COMMONS_CONFIGURATION_RELATIVE_PATH : configured;
    }

    private final ConfigurationSet configurationSet;
    private final RunContext context;
    private final SourceResolver resolver;
    private final Materializer materializer;
    private final LauncherFactory launcherFactory;
    private final TestRunner testRunner;
    private final DuplicateTestsDetector duplicateDetector;
    private final Path testServerRoot;
    private final ResultReporter reporter;

    public ESDKTestServer(
            ConfigurationSet configurationSet,
            RunContext context,
            Materializer materializer,
            LauncherFactory launcherFactory,
            TestRunner testRunner,
            DuplicateTestsDetector duplicateDetector,
            Path testServerRoot) {
        this.configurationSet = configurationSet;
        this.context = context;
        this.resolver = new SourceResolver();
        this.materializer = materializer;
        this.launcherFactory = launcherFactory;
        this.testRunner = testRunner;
        this.duplicateDetector = duplicateDetector;
        this.testServerRoot = testServerRoot;
        this.reporter = new ResultReporter();
    }

    /** Run with no Configuration_Overrides. */
    public Result run() {
        return run(List.of());
    }

    /**
     * Run the orchestrated pipeline with the invoking Language_Repository's
     * Configuration_Overrides (empty for a Commons_Run). Teardown always runs
     * in a {@code finally} (Requirement 2.6): on the primary path the close
     * results feed the reporter's cleanup failures; on abort paths the cleanup
     * information is appended to the abort result without masking it
     * (Requirement 2.11).
     */
    public Result run(List<ConfigurationEntry> overrides) {
        List<LaunchedServer> launched = new ArrayList<>();
        List<String> cleanupFailureLanguages = new ArrayList<>();
        PipelineOutcome outcome;
        try {
            outcome = executePipeline(overrides, launched);
        } finally {
            // 8. Teardown is total: stop every server launched during the run,
            // whatever the outcome (Requirement 2.6). A STILL_RUNNING close
            // result names its language for the cleanup-failure report
            // (Requirement 2.11).
            for (LaunchedServer server : launched) {
                CloseResult close = server.close();
                if (!close.isStopped()) {
                    cleanupFailureLanguages.add(close.language());
                }
            }
        }
        if (outcome.abort() != null) {
            // Cleanup failures are appended to the abort result — reported,
            // never masking the primary cause (Requirement 2.11).
            return outcome.abort().withCleanupFailures(cleanupFailureLanguages);
        }
        // 7. Fail-open reporting (Requirements 2.8, 2.10) including the KMS
        // coverage floor over the launched Target pairs (Requirement 10.4) and
        // the teardown cleanup failures (Requirement 2.11).
        return reporter.report(
            outcome.executions(), outcome.launchedLabels(), cleanupFailureLanguages);
    }

    // ------------------------------------------------------------------
    // The fail-closed pipeline (stages 1–6)
    // ------------------------------------------------------------------

    /** The pipeline's outcome: an abort {@link Result}, or the run's executions. */
    private record PipelineOutcome(
            Result abort, List<TestExecution> executions, List<String> launchedLabels) {

        static PipelineOutcome aborted(String cause) {
            return new PipelineOutcome(Result.abort(cause), null, null);
        }

        static PipelineOutcome completed(List<TestExecution> executions, List<String> labels) {
            return new PipelineOutcome(null, executions, labels);
        }
    }

    /**
     * One language's Feature_Declaration, wherever it was carried, with its
     * optional raw-RSA padding capability ({@code null} = every scheme).
     */
    private record Declaration(
            List<String> supported, List<String> unsupported, List<String> rawRsaPaddingSchemes) {
    }

    private PipelineOutcome executePipeline(
            List<ConfigurationEntry> overrides, List<LaunchedServer> launched) {
        // ---- Stage 1: load + validate the Configuration_Set and the on-hand
        // Feature_Declarations, all before anything is cloned. ----

        // 1a. Structural validation: the catalog (product + Feature_Catalog),
        // every entry and override, the override sanity rules, and
        // effective-set port uniqueness (Requirements 3.2, 3.8, 4.7, 4.11,
        // 7.4, 7.5).
        ConfigurationSetValidation validation = ConfigurationValidation.validate(
            configurationSet, overrides, context.ownLanguage());
        if (!validation.valid()) {
            return PipelineOutcome.aborted("invalid Configuration_Set: " + validation.message());
        }

        // 1b. Reject duplicate Tests definitions before running anything
        // (Requirement 10.1).
        List<Path> testsDefs = duplicateDetector.findTestsDefinitions(testServerRoot);
        if (testsDefs.size() > 1) {
            return PipelineOutcome.aborted("found " + testsDefs.size()
                + " Tests definitions (expected exactly one): " + testsDefs);
        }

        // The run-effective entries: each overridden language's entry replaced
        // by its Configuration_Override (Requirement 4.6).
        List<ConfigurationEntry> effectiveEntries = effectiveEntries(overrides);
        List<String> catalog = configurationSet.features();

        // 1c. On-hand Feature_Declarations (Requirements 8.4–8.11): the own
        // repository's commons-configuration file on a Language_Repository_Run
        // (declaration + product match — it is in the working tree, read
        // now), and every declaration carried inline in an effective entry.
        // Declarations obtained by materialization complete in stage 3.
        Map<String, Declaration> declarations = new LinkedHashMap<>();
        FeatureValidation.Result onHand = FeatureValidation.Result.ok();
        if (context.kind() == RunContext.Kind.LANGUAGE) {
            Path expected = context.languageRepoRoot()
                .resolve(commonsConfigurationRelativePath(
                    configurationSet.forLanguage(context.ownLanguage())));
            CommonsConfiguration own;
            try {
                own = ConfigurationLoader.loadCommonsConfiguration(expected);
            } catch (ConfigurationLoadException e) {
                // Missing/unparseable carrying file: name the language and the
                // expected Feature_Declaration location (Requirement 8.10).
                return PipelineOutcome.aborted(FeatureValidation.carryingFileError(
                    context.ownLanguage(), expected.toString(), e.getMessage()).message());
            }
            onHand = onHand
                .and(FeatureValidation.validateDeclaration(catalog, context.ownLanguage(),
                    own.supportedFeatures(), own.unsupportedFeatures()))
                .and(FeatureValidation.validateRawRsaPaddingSchemes(context.ownLanguage(),
                    own.rawRsaPaddingSchemes(), own.supportedFeatures()))
                .and(FeatureValidation.validateProductMatch(context.invokingRepositoryName(),
                    own.product(), configurationSet.product()));
            declarations.put(context.ownLanguage(),
                new Declaration(own.supportedFeatures(), own.unsupportedFeatures(),
                    own.rawRsaPaddingSchemes()));
        }
        for (ConfigurationEntry entry : effectiveEntries) {
            if (isOwnLanguage(entry) || !entry.hasFeatureDeclaration()) {
                continue;
            }
            onHand = onHand
                .and(FeatureValidation.validateDeclaration(catalog,
                    entry.language(), entry.supportedFeatures(), entry.unsupportedFeatures()))
                .and(FeatureValidation.validateRawRsaPaddingSchemes(entry.language(),
                    entry.rawRsaPaddingSchemes(), entry.supportedFeatures()));
            declarations.put(entry.language(),
                new Declaration(entry.supportedFeatures(), entry.unsupportedFeatures(),
                    entry.rawRsaPaddingSchemes()));
        }
        if (!onHand.valid()) {
            return PipelineOutcome.aborted(
                "invalid Feature_Declaration(s): " + onHand.message());
        }

        // ---- Stage 2: materialize the planned sources. Planning is pure
        // (design resolution-rules table); materialization performs the git
        // and filesystem I/O, capturing failures as data (Requirement 3.6). ----
        List<ResolvedComponentPlan> plans = resolver.resolve(configurationSet, context, overrides);
        MaterializedSources sources = materializer.materialize(plans);

        // ---- Stage 4 (emitted here so the record accompanies every
        // materialization outcome, failures included — Requirement 5.4):
        // produce + emit the Resolution_Record before any launch, any Test,
        // and the reported result (Requirement 5.6). ----
        ResolutionRecord record;
        try {
            record = ResolutionRecord.assemble(context, sources);
            System.out.println(record.toStdoutBlock());
            record.writeJson(testServerRoot.resolve(ResolutionRecord.DEFAULT_JSON_OUTPUT));
        } catch (IOException | RuntimeException e) {
            // An unproducible record fails the run before any Test, identifying
            // the production failure (Requirement 5.5).
            return PipelineOutcome.aborted(
                "could not produce the Resolution_Record: " + e.getMessage()
                    + " (Requirement 5.5)");
        }

        // Gate on record completeness (Requirement 5.5).
        Set<String> expectedLanguages = new LinkedHashSet<>();
        for (ConfigurationEntry entry : effectiveEntries) {
            expectedLanguages.add(entry.language());
        }
        if (expectedLanguages.isEmpty()) {
            return PipelineOutcome.aborted(
                "the Configuration_Set contains no Configuration_Entries");
        }
        ResolutionRecord.Completeness completeness = record.completeness(expectedLanguages);
        if (!completeness.complete()) {
            return PipelineOutcome.aborted("the Resolution_Record is incomplete: "
                + String.join("; ", completeness.problems()) + " (Requirement 5.5)");
        }

        // Gate on materialization failures: a component that could not be
        // materialized fails the run before any launch or Test, naming the
        // attempted coordinates and the cause (Requirement 3.6).
        if (!sources.allSucceeded()) {
            StringBuilder message = new StringBuilder("source materialization failed:");
            for (MaterializedSources.Failure failure : sources.failures()) {
                message.append(" [").append(failure.component())
                    .append(" from ").append(failure.attemptedRepository());
                if (failure.attemptedReference() != null) {
                    message.append(" at ").append(failure.attemptedReference());
                }
                message.append(", path ").append(failure.attemptedPath())
                    .append(": ").append(failure.cause()).append(']');
            }
            return PipelineOutcome.aborted(message.toString());
        }

        // ---- Stage 3 (completed after materialization, before any launch —
        // Requirement 8.4): Feature validation for declarations carried in
        // materialized commons-configuration files. A language whose effective
        // entry has no inline declaration carries it in its
        // Language_Repository's commons-configuration file, located under the
        // materialized Server_Location root (e.g. Java's in a Commons_Run). ----
        for (ConfigurationEntry entry : effectiveEntries) {
            if (isOwnLanguage(entry) || entry.hasFeatureDeclaration()) {
                continue;
            }
            String language = entry.language();
            Optional<MaterializedSources.Success> server =
                sources.successOf(ComponentId.server(language));
            if (server.isEmpty()) {
                // Unreachable post-gate; kept as a defensive fail-closed abort.
                return PipelineOutcome.aborted("no materialized server component for language '"
                    + language + "' to locate its Feature_Declaration");
            }
            Path expected = server.get().root().resolve(commonsConfigurationRelativePath(entry));
            CommonsConfiguration carried;
            try {
                carried = ConfigurationLoader.loadCommonsConfiguration(expected);
            } catch (ConfigurationLoadException e) {
                return PipelineOutcome.aborted(FeatureValidation.carryingFileError(
                    language, expected.toString(), e.getMessage()).message());
            }
            String languageRepository = entry.serverLocation() != null
                && entry.serverLocation().repository() != null
                ? entry.serverLocation().repository() : language;
            FeatureValidation.Result crossRepo = FeatureValidation
                .validateDeclaration(catalog, language,
                    carried.supportedFeatures(), carried.unsupportedFeatures())
                .and(FeatureValidation.validateRawRsaPaddingSchemes(language,
                    carried.rawRsaPaddingSchemes(), carried.supportedFeatures()))
                .and(FeatureValidation.validateProductMatch(languageRepository,
                    carried.product(), configurationSet.product()));
            if (!crossRepo.valid()) {
                return PipelineOutcome.aborted(
                    "invalid Feature_Declaration(s): " + crossRepo.message());
            }
            declarations.put(language,
                new Declaration(carried.supportedFeatures(), carried.unsupportedFeatures(),
                    carried.rawRsaPaddingSchemes()));
        }

        // ---- Stage 5: build + launch every server as a subprocess on its
        // configured port (Requirement 2.1), concurrently — each launch() runs
        // on its own thread and returns only when its server is reachable. A
        // language with no launcher wired aborts before any launch. Every
        // concurrent launch is awaited, so a server that came up is recorded in
        // {@code launched} for teardown even when another language's launch
        // aborts the run; the abort names the failing language and the cause
        // (Requirements 2.5, 2.6). ----
        for (ConfigurationEntry entry : effectiveEntries) {
            if (launcherFactory.launcherFor(entry.language()).isEmpty()) {
                return PipelineOutcome.aborted(
                    "no Language_Server launcher is available for language '"
                        + entry.language() + "'");
            }
        }
        ExecutorService launchPool =
            Executors.newFixedThreadPool(Math.max(1, effectiveEntries.size()));
        List<Future<LaunchedServer>> launchFutures = new ArrayList<>();
        try {
            for (ConfigurationEntry entry : effectiveEntries) {
                Launcher launcher = launcherFactory.launcherFor(entry.language()).orElseThrow();
                launchFutures.add(launchPool.submit(() -> launcher.launch(entry, sources)));
            }
        } finally {
            launchPool.shutdown();
        }
        ServerLaunchException launchFailure = null;
        RuntimeException launchError = null;
        for (Future<LaunchedServer> future : launchFutures) {
            try {
                launched.add(future.get());
            } catch (ExecutionException e) {
                if (e.getCause() instanceof ServerLaunchException sle) {
                    if (launchFailure == null) {
                        launchFailure = sle;
                    }
                } else if (launchError == null) {
                    launchError = new RuntimeException(
                        "unexpected failure launching a Language_Server", e.getCause());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                if (launchError == null) {
                    launchError = new RuntimeException(
                        "interrupted while launching the Language_Servers", e);
                }
            }
        }
        if (launchError != null) {
            throw launchError;
        }
        if (launchFailure != null) {
            return PipelineOutcome.aborted("failed to launch the " + launchFailure.language()
                + " Language_Server [" + launchFailure.category() + "]: "
                + launchFailure.getMessage());
        }

        // Final reachability re-check across all launched ports: Tests begin
        // only after every configured Language_Server is reachable
        // (Requirements 2.3, 2.9) — a server that came up but died while later
        // servers launched is caught here, not mid-Tests.
        for (LaunchedServer server : launched) {
            if (!server.reachable()) {
                return PipelineOutcome.aborted("the " + server.language()
                    + " Language_Server is no longer reachable on its configured port "
                    + server.port() + " (Requirement 2.3)");
            }
        }

        // ---- Stage 6: run the Tests, pointed at the launched Targets via
        // runtime configuration only (Requirements 2.2, 10.2), with every
        // language's Feature_Declaration — inline, own working tree, and
        // cross-repo alike — flattened for the FeatureGate (Requirement 9.3). ----
        TestRunInput input = testRunInput(effectiveEntries, launched, declarations);
        List<TestExecution> executions;
        try {
            executions = testRunner.run(input);
        } catch (MissingRuntimeConfigException e) {
            return PipelineOutcome.aborted(e.getMessage());
        }
        List<String> launchedLabels = input.targets().stream()
            .map(t -> t.language() + "-v" + t.majorVersion())
            .toList();
        return PipelineOutcome.completed(executions, launchedLabels);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Assemble the {@link TestRunInput} from the launched servers, the
     * run-effective entries, and every validated Feature_Declaration: the
     * launched Targets (Requirement 2.2), each declaration flattened to
     * booleans, and the Feature_Catalog verbatim (Requirement 9.3).
     */
    private TestRunInput testRunInput(
            List<ConfigurationEntry> effectiveEntries,
            List<LaunchedServer> launched,
            Map<String, Declaration> declarations) {
        Map<String, ConfigurationEntry> entryByLanguage = new LinkedHashMap<>();
        for (ConfigurationEntry entry : effectiveEntries) {
            entryByLanguage.put(entry.language(), entry);
        }

        List<TestTarget> targets = new ArrayList<>();
        for (LaunchedServer server : launched) {
            ConfigurationEntry entry = entryByLanguage.get(server.language());
            int majorVersion = entry != null && entry.majorVersion() != null
                ? entry.majorVersion() : 0;
            targets.add(new TestTarget(server.language(), majorVersion, server.endpoint()));
        }

        List<String> catalog = configurationSet.features() == null
            ? List.of() : configurationSet.features();
        Map<String, Map<String, Boolean>> features = new LinkedHashMap<>();
        Map<String, List<String>> rawRsaPaddingSchemes = new LinkedHashMap<>();
        for (ConfigurationEntry entry : effectiveEntries) {
            Declaration declaration = declarations.get(entry.language());
            if (declaration == null) {
                continue;
            }
            Map<String, Boolean> flattened = TestRunInput.flattenDeclaration(
                catalog, declaration.supported(), declaration.unsupported());
            if (!flattened.isEmpty()) {
                features.put(entry.language(), flattened);
            }
            if (declaration.rawRsaPaddingSchemes() != null) {
                rawRsaPaddingSchemes.put(entry.language(), declaration.rawRsaPaddingSchemes());
            }
        }
        return new TestRunInput(targets, features, catalog, rawRsaPaddingSchemes);
    }

    private boolean isOwnLanguage(ConfigurationEntry entry) {
        return context.kind() == RunContext.Kind.LANGUAGE
            && entry.language() != null
            && entry.language().equals(context.ownLanguage());
    }

    private List<ConfigurationEntry> effectiveEntries(List<ConfigurationEntry> overrides) {
        Map<String, ConfigurationEntry> overrideByLanguage = new LinkedHashMap<>();
        for (ConfigurationEntry override : overrides) {
            overrideByLanguage.put(override.language(), override);
        }
        List<ConfigurationEntry> effective = new ArrayList<>();
        for (ConfigurationEntry stored : configurationSet.entries()) {
            boolean ownLanguage = stored.language().equals(context.ownLanguage());
            ConfigurationEntry override =
                ownLanguage ? null : overrideByLanguage.get(stored.language());
            effective.add(override != null ? override : stored);
        }
        return effective;
    }
}
