package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSetValidation;
import aws.cryptography.esdk.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.esdk.testserver.orchestrator.report.Result;
import aws.cryptography.esdk.testserver.orchestrator.report.ResultReporter;
import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunner;
import aws.cryptography.esdk.testserver.orchestrator.source.Override;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedSource;
import aws.cryptography.esdk.testserver.orchestrator.source.SourceResolution;
import aws.cryptography.esdk.testserver.orchestrator.source.SourceResolver;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The ESDK TestServer orchestrator — the executable closure over the
 * {@code Configuration_Set}, the source-resolution overrides, and the launched
 * {@code Language_Server}s (design "The Closure / Orchestrator"):
 *
 * <pre>{@code
 *   ESDKTestServer(Optional<Path> liveSourceCode,
 *                  Optional<Override>... perLanguageOverrides) -> Result<Boolean>
 * }</pre>
 *
 * <p>Here {@code Live} source is expressed as an {@link Override.Live} in the
 * overrides list (carrying the language it belongs to). Invoked with no overrides
 * the run targets the head of every configured branch/repository (Requirement
 * 10.2).
 *
 * <p>Responsibilities, in order (each abort runs no {@code Tests}, records no
 * partial results, and returns a fail-open failure identifying the cause):
 * <ol>
 *   <li>Validate the {@code Configuration_Set} (Requirements 9.2, 9.3, 9.5).</li>
 *   <li>Reject duplicate {@code Tests} definitions (Requirement 7.5).</li>
 *   <li>Resolve each language to one effective source; reject conflicting
 *       consumption inputs (Requirements 10-12, 11.5, 12.9).</li>
 *   <li>Build + launch each server on its configured port; reject build failures,
 *       unresolvable references, and port conflicts (Requirements 9.4, 9.6, 11.4,
 *       12.8).</li>
 *   <li>Point the single Java {@code Tests} at the launched endpoints via runtime
 *       configuration only; refuse to run without a configured endpoint
 *       (Requirements 7.2-7.4).</li>
 *   <li>Report a fail-open {@link Result} (Requirements 11.3, 13.1-13.4).</li>
 * </ol>
 */
public final class ESDKTestServer {

    private final ConfigurationSet configurationSet;
    private final SourceResolver resolver;
    private final Launcher launcher;
    private final TestRunner testRunner;
    private final DuplicateTestsDetector duplicateDetector;
    private final Path testServerRoot;
    private final ResultReporter reporter;

    public ESDKTestServer(
            ConfigurationSet configurationSet,
            Launcher launcher,
            TestRunner testRunner,
            DuplicateTestsDetector duplicateDetector,
            Path testServerRoot) {
        this.configurationSet = configurationSet;
        this.resolver = new SourceResolver();
        this.launcher = launcher;
        this.testRunner = testRunner;
        this.duplicateDetector = duplicateDetector;
        this.testServerRoot = testServerRoot;
        this.reporter = new ResultReporter();
    }

    /** Run with no overrides — head of every configured branch/repository (Req 10.2). */
    public Result run() {
        return run(List.of());
    }

    /** Run the closure with the given per-language overrides. */
    public Result run(List<Override> overrides) {
        // 1. Validate the Configuration_Set; abort without starting any server
        //    if any entry is malformed or two entries share a port (Req 9.5).
        ConfigurationSetValidation validation = configurationSet.validate();
        if (!validation.valid()) {
            return Result.abort("invalid Configuration_Set: " + validation.message());
        }

        // 2. Reject duplicate Tests definitions before running anything (Req 7.5).
        List<Path> testsDefs = duplicateDetector.findTestsDefinitions(testServerRoot);
        if (testsDefs.size() > 1) {
            return Result.abort("found " + testsDefs.size()
                + " Tests definitions (expected exactly one): " + testsDefs);
        }

        // 3. Resolve each language to its single effective source; abort on
        //    conflicting consumption inputs (Requirements 11.5, 12.9).
        SourceResolution resolution = resolver.resolve(configurationSet, overrides);
        if (!resolution.isResolved()) {
            return Result.abort(resolution.failure().orElse("source resolution failed"));
        }

        // 4. Build + launch each server on its configured port (Req 9.4). Any
        //    build failure / unresolvable reference / port conflict aborts the run,
        //    naming the language (Requirements 9.6, 11.4, 12.8).
        List<LaunchedServer> launched = new ArrayList<>();
        try {
            for (ConfigurationEntry entry : configurationSet.entries()) {
                ResolvedSource source = resolution.sources().get(entry.language());
                try {
                    launched.add(launcher.launch(entry, source));
                } catch (ServerLaunchException e) {
                    return Result.abort("failed to launch the " + e.language()
                        + " Language_Server [" + e.category() + "]: " + e.getMessage());
                }
            }

            // 5. Point the single Java Tests at the launched endpoints via runtime
            //    configuration only (Req 7.2, 7.3); refuse if none (Req 7.4).
            List<URI> endpoints = launched.stream().map(LaunchedServer::endpoint).toList();
            List<TestExecution> executions;
            try {
                executions = testRunner.run(endpoints);
            } catch (MissingRuntimeConfigException e) {
                return Result.abort(e.getMessage());
            }

            // 6. Fail-open reporting (Requirements 11.3, 13.1-13.4).
            return reporter.report(executions);
        } finally {
            // Always stop every server we launched, whatever the outcome.
            for (LaunchedServer server : launched) {
                server.close();
            }
        }
    }
}
