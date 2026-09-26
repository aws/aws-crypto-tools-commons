package aws.cryptography.testserver.orchestrator;

import aws.cryptography.testserver.orchestrator.config.ServerConfiguration;
import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.config.ConfigurationLoadException;
import aws.cryptography.testserver.orchestrator.config.ConfigurationLoader;
import aws.cryptography.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.testserver.orchestrator.config.CommonsConfigurationValidation;
import aws.cryptography.testserver.orchestrator.config.ConfigurationValidation;
import aws.cryptography.testserver.orchestrator.config.FeatureValidation;
import aws.cryptography.testserver.orchestrator.launch.CloseResult;
import aws.cryptography.testserver.orchestrator.launch.LaunchTimings;
import aws.cryptography.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.testserver.orchestrator.launch.Launcher;
import aws.cryptography.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.testserver.orchestrator.record.ResolutionRecord;
import aws.cryptography.testserver.orchestrator.report.Result;
import aws.cryptography.testserver.orchestrator.report.ResultReporter;
import aws.cryptography.testserver.orchestrator.report.TestExecution;
import aws.cryptography.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.testserver.orchestrator.run.TestRunner;
import aws.cryptography.testserver.orchestrator.run.TestTarget;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.Materializer;
import aws.cryptography.testserver.orchestrator.source.ResolvedComponentPlan;
import aws.cryptography.testserver.orchestrator.source.RunContext;
import aws.cryptography.testserver.orchestrator.source.SourceResolver;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
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
 * {@code commons configuration}, the {@link RunContext}, any
 * Configuration_Overrides, and the launched {@code Language_Server}s.
 *
 * <p>The stages — any stage 1–5 failure runs zero
 * {@code Tests}, records no partial results, and reports a fail-open failure
 * identifying the language (where one applies) and the cause:
 * <ol>
 *   <li>Load + validate the {@code commons configuration} and the on-hand
 *       Feature_Declarations: structural validation before anything is cloned,
 *       the duplicate-Tests check, every Feature_Declaration carried inline in
 *       an effective entry, and — on a Language_Repository_Run — the own
 *       repository's commons-configuration file (declaration + product match).</li>
 *   <li>Materialize the planned sources: pure resolution planning, then git
 *       clones / working-tree checks.</li>
 *   <li>Complete Feature validation for declarations obtained by
 *       materialization — a language whose effective entry carries no inline
 *       declaration reads it from
 *       {@code <server root>/<product>/test-server/server-config.json}
 *       (e.g. Java's in a Commons_Run), including the product match.</li>
 *   <li>Produce + emit the Resolution_Record — stdout block and
 *       {@code build/resolution-record.json} — <em>before</em>
 *       any launch, any Test, and the reported result,
 *       failures included; gate on completeness, then on materialization
 *       failures. (Emission precedes the stage-3 checks in code so
 *       the record always accompanies a materialization-failure abort.)</li>
 *   <li>Build + launch every server on its configured port, then re-check
 *       reachability across all launched ports — Tests start only after every
 *       server is reachable.</li>
 *   <li>Run the Tests with the targets / features / featureCatalog runtime
 *       properties.</li>
 *   <li>Report the fail-open {@link Result} including the KMS coverage floor.</li>
 *   <li>Teardown in {@code finally}, whatever the outcome;
 *       {@code STILL_RUNNING} close results feed the report's cleanup
 *       failures without ever masking the primary result.</li>
 * </ol>
 */
public final class TestServerOrchestrator {

    /**
     * The DEFAULT repository-root-relative location of a Language_Repository's
     * per-server {@code server-config.json}:
     * {@code <product>/test-server/server-config.json}, where {@code product}
     * names the SDK the current run belongs to (from the commons configuration).
     * A Configuration_Entry whose Language_Repository places the trio elsewhere
     * overrides this via {@code configPath}.
     */
    static String defaultServerConfigurationRelativePath(String product) {
        return product + "/test-server/server-config.json";
    }

    /**
     * The repository-root-relative path to {@code entry}'s per-server
     * {@code server-config.json}: the entry's {@code configPath} (a directory)
     * when set, otherwise the default derived from {@code product}. Lets a
     * Language_Repository whose layout differs from the default (e.g. the Rust
     * server, whose sources live under {@code esdk-test-server/}) carry its
     * trio alongside them.
     */
    static String serverConfigurationRelativePath(ConfigurationEntry entry, String product) {
        String configured = entry == null ? null : entry.configPath();
        if (configured == null || configured.isBlank()) {
            return defaultServerConfigurationRelativePath(product);
        }
        // The doc's configPath is the DIRECTORY holding the per-server trio;
        // the per-server declaration file within it is server-config.json.
        return configured + "/server-config.json";
    }

    /**
     * The DEFAULT reference implementation: the language whose Language_Server
     * plays the immaterial side of single-sided Tests (the Tests read it from
     * {@code testserver.referenceImplementation}). Overridden per
     * invocation via the {@code referenceImplementation} CLI argument.
     */
    public static final String DEFAULT_REFERENCE_IMPLEMENTATION = "java";

    private final CommonsConfiguration commonsConfiguration;
    private final RunContext context;
    private final SourceResolver resolver;
    private final Materializer materializer;
    private final LauncherFactory launcherFactory;
    private final TestRunner testRunner;
    private final DuplicateTestsDetector duplicateDetector;
    private final Path testServerRoot;
    private final String referenceImplementation;
    private Set<String> languages = Set.of();
    private StopAfter stopAfter = StopAfter.NONE;
    private final ResultReporter reporter;

    /**
     * Per-repository working-tree overlays: repository-name → local working-
     * tree root that pre-empts any clone. Zero or more may be supplied via the
     * {@code workingTreeOverlay.<repo>=<abs path>} CLI arg. Lets a Commons_Run
     * consume a sibling repository's uncommitted working tree the same way it
     * consumes a committed clone. Own-language (LANGUAGE-run) still uses
     * {@code languageRepoRoot} regardless.
     */
    private Map<String, Path> workingTreeOverlays = Map.of();

    /** With the {@link #DEFAULT_REFERENCE_IMPLEMENTATION}. */
    public TestServerOrchestrator(
            CommonsConfiguration commonsConfiguration,
            RunContext context,
            Materializer materializer,
            LauncherFactory launcherFactory,
            TestRunner testRunner,
            DuplicateTestsDetector duplicateDetector,
            Path testServerRoot) {
        this(commonsConfiguration, context, materializer, launcherFactory, testRunner,
            duplicateDetector, testServerRoot, DEFAULT_REFERENCE_IMPLEMENTATION);
    }

    public TestServerOrchestrator(
            CommonsConfiguration commonsConfiguration,
            RunContext context,
            Materializer materializer,
            LauncherFactory launcherFactory,
            TestRunner testRunner,
            DuplicateTestsDetector duplicateDetector,
            Path testServerRoot,
            String referenceImplementation) {
        this.commonsConfiguration = commonsConfiguration;
        this.context = context;
        this.resolver = new SourceResolver();
        this.materializer = materializer;
        this.launcherFactory = launcherFactory;
        this.testRunner = testRunner;
        this.duplicateDetector = duplicateDetector;
        this.testServerRoot = testServerRoot;
        this.referenceImplementation = referenceImplementation;
        // The KMS coverage floor is an SDK-opt-in policy:
        // each SDK declares its scenario list in its commons configuration's
        // requiredKmsScenarios (absent -> empty list -> floor off). Shared
        // code carries no per-product knowledge; the SDK's config is the
        // sole source of truth.
        List<String> configured = commonsConfiguration == null
            ? null : commonsConfiguration.requiredKmsScenarios();
        this.reporter = new ResultReporter(configured == null ? List.of() : configured);
    }

    /**
     * Attach a set of per-repository working-tree overlays. Any component
     * whose library or Server_Location repository name is a key in this map
     * resolves to a {@link aws.cryptography.testserver.orchestrator.source.SourcePlan.WorkingTree}
     * rooted at the corresponding path — no matter the run context. Overrides
     * still win; own-language (LANGUAGE-run) still uses
     * {@code languageRepoRoot} unchanged
     * (see {@link SourceResolver#resolve(CommonsConfiguration, RunContext, List, Map)}).
     *
     * @return this orchestrator, for chaining
     */
    public TestServerOrchestrator withWorkingTreeOverlays(Map<String, Path> overlays) {
        this.workingTreeOverlays = overlays == null ? Map.of() : Map.copyOf(overlays);
        return this;
    }

    /** Where a run stops early; {@link #NONE} runs the Tests. */
    public enum StopAfter {
        /** Run the whole pipeline, Tests included. */
        NONE,
        /** Stop once every source is materialized (clones only). */
        MATERIALIZE,
        /** Stop once every server has been built and reached, then tear down. */
        LAUNCH
    }

    /**
     * Restrict the run to {@code languages} (every other configured language
     * is neither resolved, built, nor tested). Empty runs every language.
     *
     * @return this orchestrator, for chaining
     */
    public TestServerOrchestrator withLanguages(Set<String> languages) {
        this.languages = languages == null ? Set.of() : Set.copyOf(languages);
        return this;
    }

    /** @return this orchestrator, stopping after {@code stopAfter}, for chaining */
    public TestServerOrchestrator withStopAfter(StopAfter stopAfter) {
        this.stopAfter = stopAfter == null ? StopAfter.NONE : stopAfter;
        return this;
    }

    /** Run with no Configuration_Overrides. */
    public Result run() {
        return run(List.of());
    }

    /**
     * Run the orchestrated pipeline with the invoking Language_Repository's
     * Configuration_Overrides (empty for a Commons_Run). Teardown always runs
     * in a {@code finally}: on the primary path the close
     * results feed the reporter's cleanup failures; on abort paths the cleanup
     * information is appended to the abort result without masking it.
     */
    public Result run(List<ConfigurationEntry> overrides) {
        List<LaunchedServer> launched = new ArrayList<>();
        List<String> cleanupFailureLanguages = new ArrayList<>();
        PipelineOutcome outcome;
        try {
            outcome = executePipeline(overrides, launched);
        } finally {
            // 8. Teardown is total: stop every server launched during the run,
            // whatever the outcome. A STILL_RUNNING close
            // result names its language for the cleanup-failure report.
            for (LaunchedServer server : launched) {
                CloseResult close = server.close();
                if (!close.isStopped()) {
                    cleanupFailureLanguages.add(close.language());
                }
            }
        }
        if (outcome.stopped() != null) {
            return outcome.stopped().withCleanupFailures(cleanupFailureLanguages);
        }
        if (outcome.abort() != null) {
            // Cleanup failures are appended to the abort result — reported,
            // never masking the primary cause.
            return outcome.abort().withCleanupFailures(cleanupFailureLanguages);
        }
        // 7. Fail-open reporting including the KMS
        // coverage floor over the launched Target pairs and
        // the teardown cleanup failures.
        return reporter.report(
            outcome.executions(), outcome.launchedLabels(), cleanupFailureLanguages);
    }

    // ------------------------------------------------------------------
    // The fail-closed pipeline (stages 1–6)
    // ------------------------------------------------------------------

    /** The pipeline's outcome: an abort {@link Result}, or the run's executions. */
    private record PipelineOutcome(
            Result abort, Result stopped, List<TestExecution> executions,
            List<String> launchedLabels) {

        static PipelineOutcome aborted(String cause) {
            return new PipelineOutcome(Result.abort(cause), null, null, null);
        }

        static PipelineOutcome stoppedAfter(StopAfter stage, List<ConfigurationEntry> entries) {
            List<String> languages = entries.stream().map(ConfigurationEntry::language).toList();
            return new PipelineOutcome(null, Result.success(
                "stopped after " + stage.name().toLowerCase(java.util.Locale.ROOT)
                    + " (no Tests run)", languages), null, null);
        }

        static PipelineOutcome completed(List<TestExecution> executions, List<String> labels) {
            return new PipelineOutcome(null, null, executions, labels);
        }
    }

    /**
     * One language's Feature_Declaration, wherever it was carried, with its
     * optional raw-RSA padding capability ({@code null} = every scheme) and the
     * bug ids it exhibits (empty = none / no bug ledger).
     */
    private record Declaration(
            List<String> supported, List<String> unsupported, List<String> rawRsaPaddingSchemes,
            List<String> bugIds) {
    }

    private PipelineOutcome executePipeline(
            List<ConfigurationEntry> overrides, List<LaunchedServer> launched) {
        // ---- Stage 1: load + validate the commons configuration and the on-hand
        // Feature_Declarations, all before anything is cloned. ----

        // 1a. Structural validation: the catalog (product + Feature_Catalog),
        // every entry and override, the override sanity rules, and
        // effective-set port uniqueness.
        CommonsConfigurationValidation validation = ConfigurationValidation.validate(
            commonsConfiguration, overrides, context.ownLanguage());
        if (!validation.valid()) {
            return PipelineOutcome.aborted("invalid commons configuration: " + validation.message());
        }

        // 1a'. The reference implementation must be a configured language: the
        // Tests produce single-sided messages on its Language_Server, so an
        // unknown value aborts before anything is cloned, naming it and the
        // configured languages.
        CommonsConfigurationValidation reference = ConfigurationValidation
            .validateReferenceImplementation(commonsConfiguration, referenceImplementation);
        if (!reference.valid()) {
            return PipelineOutcome.aborted(
                "invalid referenceImplementation: " + reference.message());
        }

        // 1b. Reject duplicate Tests definitions before running anything.
        List<Path> testsDefs = duplicateDetector.findTestsDefinitions(
            testServerRoot, commonsConfiguration.product());
        if (testsDefs.size() > 1) {
            return PipelineOutcome.aborted("found " + testsDefs.size()
                + " Tests definitions (expected exactly one): " + testsDefs);
        }

        // The run-effective entries: each overridden language's entry replaced
        // by its Configuration_Override.
        List<ConfigurationEntry> effectiveEntries = effectiveEntries(overrides);
        if (!languages.isEmpty()) {
            Set<String> configured = new LinkedHashSet<>();
            effectiveEntries.forEach(entry -> configured.add(entry.language()));
            if (!configured.containsAll(languages)) {
                return PipelineOutcome.aborted("languages " + languages
                    + " must all be configured languages " + configured);
            }
            effectiveEntries = effectiveEntries.stream()
                .filter(entry -> languages.contains(entry.language()))
                .toList();
        }
        List<String> catalog = commonsConfiguration.features();

        // 1c. On-hand Feature_Declarations: the own
        // repository's commons-configuration file on a Language_Repository_Run
        // (declaration + product match — it is in the working tree, read
        // now), and every declaration carried inline in an effective entry.
        // Declarations obtained by materialization complete in stage 3.
        Map<String, Declaration> declarations = new LinkedHashMap<>();
        FeatureValidation.Result onHand = FeatureValidation.Result.ok();
        if (context.kind() == RunContext.Kind.LANGUAGE) {
            Path expected = context.languageRepoRoot()
                .resolve(serverConfigurationRelativePath(
                    commonsConfiguration.forLanguage(context.ownLanguage()),
                    commonsConfiguration.product()));
            ServerConfiguration own;
            try {
                own = ConfigurationLoader.loadServerConfiguration(expected);
            } catch (ConfigurationLoadException e) {
                // Missing/unparseable carrying file: name the language and the
                // expected Feature_Declaration location.
                return PipelineOutcome.aborted(FeatureValidation.carryingFileError(
                    context.ownLanguage(), expected.toString(), e.getMessage()).message());
            }
            onHand = onHand
                .and(FeatureValidation.validateDeclaration(catalog, context.ownLanguage(),
                    own.supportedFeatures(), own.unsupportedFeatures()))
                .and(FeatureValidation.validateRawRsaPaddingSchemes(context.ownLanguage(),
                    own.rawRsaPaddingSchemes(), own.supportedFeatures()))
                .and(FeatureValidation.validateProductMatch(context.invokingRepositoryName(),
                    own.product(), commonsConfiguration.product()));
            declarations.put(context.ownLanguage(),
                new Declaration(own.supportedFeatures(), own.unsupportedFeatures(),
                    own.rawRsaPaddingSchemes(), own.bugIds()));
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
                    entry.rawRsaPaddingSchemes(), List.of()));
        }
        if (!onHand.valid()) {
            return PipelineOutcome.aborted(
                "invalid Feature_Declaration(s): " + onHand.message());
        }

        // ---- Stage 2: materialize the planned sources. Planning is pure;
        // materialization performs the git
        // and filesystem I/O, capturing failures as data. ----
        List<ResolvedComponentPlan> plans = resolver.resolve(
            commonsConfiguration, context, overrides, workingTreeOverlays);
        if (!languages.isEmpty()) {
            plans = plans.stream()
                .filter(plan -> plan.component().kind() == ComponentId.Kind.COMMONS
                    || languages.contains(plan.component().language()))
                .toList();
        }
        Instant materializeStartedAt = Instant.now();
        MaterializedSources sources = materializer.materialize(plans);
        LaunchTimings.log("all", "source materialization (git)", materializeStartedAt);

        // ---- Stage 4 (emitted here so the record accompanies every
        // materialization outcome, failures included):
        // produce + emit the Resolution_Record before any launch, any Test,
        // and the reported result. ----
        ResolutionRecord record;
        try {
            record = ResolutionRecord.assemble(context, sources);
            System.out.println(record.toStdoutBlock());
            record.writeJson(testServerRoot.resolve(ResolutionRecord.DEFAULT_JSON_OUTPUT));
        } catch (IOException | RuntimeException e) {
            // An unproducible record fails the run before any Test, identifying
            // the production failure.
            return PipelineOutcome.aborted(
                "could not produce the Resolution_Record: " + e.getMessage());
        }

        // Gate on record completeness.
        Set<String> expectedLanguages = new LinkedHashSet<>();
        for (ConfigurationEntry entry : effectiveEntries) {
            expectedLanguages.add(entry.language());
        }
        if (expectedLanguages.isEmpty()) {
            return PipelineOutcome.aborted(
                "the commons configuration contains no Configuration_Entries");
        }
        ResolutionRecord.Completeness completeness = record.completeness(expectedLanguages);
        if (!completeness.complete()) {
            return PipelineOutcome.aborted("the Resolution_Record is incomplete: "
                + String.join("; ", completeness.problems()));
        }

        // Gate on materialization failures: a component that could not be
        // materialized fails the run before any launch or Test, naming the
        // attempted coordinates and the cause.
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
        if (stopAfter == StopAfter.MATERIALIZE) {
            return PipelineOutcome.stoppedAfter(stopAfter, effectiveEntries);
        }

        // ---- Stage 3 (completed after materialization, before any launch):
        // Feature validation for declarations carried in
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
            Path expected = server.get().root().resolve(serverConfigurationRelativePath(entry, commonsConfiguration.product()));
            ServerConfiguration carried;
            try {
                carried = ConfigurationLoader.loadServerConfiguration(expected);
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
                    carried.product(), commonsConfiguration.product()));
            if (!crossRepo.valid()) {
                return PipelineOutcome.aborted(
                    "invalid Feature_Declaration(s): " + crossRepo.message());
            }
            declarations.put(language,
                new Declaration(carried.supportedFeatures(), carried.unsupportedFeatures(),
                    carried.rawRsaPaddingSchemes(), carried.bugIds()));
        }

        // ---- Stage 5: build + launch every server as a subprocess on its
        // configured port, concurrently — each launch() runs
        // on its own thread and returns only when its server is reachable. A
        // language with no launcher wired aborts before any launch. Every
        // concurrent launch is awaited, so a server that came up is recorded in
        // {@code launched} for teardown even when another language's launch
        // aborts the run; the abort names the failing language and the cause. ----
        for (ConfigurationEntry entry : effectiveEntries) {
            if (launcherFactory.launcherFor(entry.language()).isEmpty()) {
                return PipelineOutcome.aborted(
                    "no Language_Server launcher is available for language '"
                        + entry.language() + "'");
            }
        }
        Instant launchStageStartedAt = Instant.now();
        ExecutorService launchPool =
            Executors.newFixedThreadPool(Math.max(1, effectiveEntries.size()));
        List<Future<LaunchedServer>> launchFutures = new ArrayList<>();
        try {
            for (ConfigurationEntry entry : effectiveEntries) {
                Launcher launcher = launcherFactory.launcherFor(entry.language()).orElseThrow();
                launchFutures.add(launchPool.submit(() -> {
                    Instant languageStartedAt = Instant.now();
                    try {
                        return launcher.launch(entry, sources);
                    } finally {
                        LaunchTimings.log(entry.language(), "TOTAL build + launch", languageStartedAt);
                    }
                }));
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
        LaunchTimings.log("all", "launch stage (every server reachable)", launchStageStartedAt);
        LaunchTimings.printSummary("Language_Server build + launch timings");
        if (launchError != null) {
            return PipelineOutcome.aborted(launchError.getMessage());
        }
        if (launchFailure != null) {
            return PipelineOutcome.aborted("failed to launch the " + launchFailure.language()
                + " Language_Server [" + launchFailure.category() + "]: "
                + launchFailure.getMessage());
        }

        // Final reachability re-check across all launched ports: Tests begin
        // only after every configured Language_Server is reachable — a
        // server that came up but died while later
        // servers launched is caught here, not mid-Tests.
        for (LaunchedServer server : launched) {
            if (!server.reachable()) {
                return PipelineOutcome.aborted("the " + server.language()
                    + " Language_Server is no longer reachable on its configured port "
                    + server.port());
            }
        }

        if (stopAfter == StopAfter.LAUNCH) {
            return PipelineOutcome.stoppedAfter(stopAfter, effectiveEntries);
        }

        // ---- Stage 6: run the Tests, pointed at the launched Targets via
        // runtime configuration only, with every
        // language's Feature_Declaration — inline, own working tree, and
        // cross-repo alike — flattened for the FeatureGate. ----
        TestRunInput input = testRunInput(effectiveEntries, launched, declarations);
        List<TestExecution> executions;
        Instant testsStartedAt = Instant.now();
        try {
            executions = testRunner.run(input);
        } catch (MissingRuntimeConfigException e) {
            return PipelineOutcome.aborted(e.getMessage());
        } finally {
            LaunchTimings.log("all", "Tests run (gradle test)", testsStartedAt);
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
     * launched Targets, each declaration flattened to
     * booleans, and the Feature_Catalog verbatim.
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
            String repo = entry != null && entry.repository() != null
                ? entry.repository() : "unknown";
            targets.add(new TestTarget(server.language(), majorVersion, repo, server.endpoint()));
        }

        List<String> catalog = commonsConfiguration.features() == null
            ? List.of() : commonsConfiguration.features();
        Map<String, Map<String, Boolean>> features = new LinkedHashMap<>();
        Map<String, List<String>> rawRsaPaddingSchemes = new LinkedHashMap<>();
        Map<String, List<String>> knownBugs = new LinkedHashMap<>();
        List<String> bugLedgerIds = commonsConfiguration.bugLedgerIds();
        for (ConfigurationEntry entry : effectiveEntries) {
            Declaration declaration = declarations.get(entry.language());
            if (declaration == null) {
                continue;
            }
            // Every per-source registry (features, raw-RSA paddings, known bugs)
            // is keyed by the full (language, majorVersion, repo) source identity.
            int major = entry.majorVersion() != null ? entry.majorVersion() : 0;
            String repo = entry.repository() != null ? entry.repository() : "unknown";
            String sourceKey = entry.language() + ":" + major + ":" + repo;
            Map<String, Boolean> flattened = TestRunInput.flattenDeclaration(
                catalog, declaration.supported(), declaration.unsupported());
            if (!flattened.isEmpty()) {
                features.put(sourceKey, flattened);
            }
            if (declaration.rawRsaPaddingSchemes() != null) {
                rawRsaPaddingSchemes.put(sourceKey, declaration.rawRsaPaddingSchemes());
            }
            // Each exhibited bug id must be defined in the commons bug ledger:
            // a server cannot declare a bug the
            // ledger does not catalog.
            List<String> exhibited = declaration.bugIds();
            if (exhibited != null && !exhibited.isEmpty()) {
                for (String id : exhibited) {
                    if (!bugLedgerIds.contains(id)) {
                        throw new IllegalStateException(
                            "server '" + entry.language() + "' exhibits bug '" + id
                                + "' which is not defined in the commons bug ledger "
                                + bugLedgerIds);
                    }
                }
                knownBugs.put(sourceKey, exhibited);
            }
        }
        return new TestRunInput(
            targets, features, catalog, rawRsaPaddingSchemes, referenceImplementation, knownBugs);
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
        for (ConfigurationEntry stored : commonsConfiguration.entries()) {
            boolean ownLanguage = stored.language().equals(context.ownLanguage());
            ConfigurationEntry override =
                ownLanguage ? null : overrideByLanguage.get(stored.language());
            effective.add(override != null ? override : stored);
        }
        return effective;
    }
}
