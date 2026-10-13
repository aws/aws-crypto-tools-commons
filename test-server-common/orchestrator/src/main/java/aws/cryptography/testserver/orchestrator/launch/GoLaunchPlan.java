package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Go {@code Language_Server} launch plan: builds the rpcv2Cbor server that
 * ships in aws-encryption-sdk ({@code esdk-test-servers/go/}) and delegates to
 * the real AWS Encryption SDK for Go (a go.mod replace directive), from the
 * run's <em>resolved</em> sources.
 *
 * <ol>
 *   <li><b>Resolve.</b> The server directory (the {@code esdk-test-servers/go}
 *       path within the materialized aws-encryption-sdk clone) comes from the
 *       {@link MaterializedSources}; the library it replaces to is in the same
 *       clone. A missing component is a {@code RESOLVE} launch failure
 *       (Requirement 2.5).</li>
 *   <li><b>Transpile the library.</b> When the library component is a
 *       smithy-dafny {@code runtimes/go} directory ({@link DafnyProject}), its
 *       Dafny-generated packages (and the MPL's, which the server replaces to
 *       inside the {@code mpl} submodule) are not committed: in the clone root,
 *       initialize each present Dafny submodule, then {@code make
 *       _no_extern_pre_transpile transpile_dependencies_go
 *       transpile_implementation_go _no_extern_post_transpile CORES=4} in the
 *       library's project directory, the repository's {@code transpile_go}
 *       without its tests, with {@code JAVA_HOME} set to
 *       {@value DafnyProject#CODEGEN_JAVA_HOME_VARIABLE} when that is set
 *       (the Makefile runs the smithy-dafny Gradle wrapper). Dafny
 *       {@value #REQUIRED_DAFNY_VERSION} and {@code goimports} must be on
 *       {@code PATH}; a missing {@code dafny} is an eager {@code BUILD}
 *       failure. Any other library is built directly.</li>
 *   <li><b>Build.</b> {@code go build -buildvcs=false -o esdk-test-server .} in
 *       the server directory ({@code -buildvcs=false} because the materialized
 *       clone trips Go's git VCS stamping). A non-zero build is a {@code BUILD}
 *       launch failure carrying the tool output.</li>
 *   <li><b>Launch.</b> {@code <server>/esdk-test-server <port>} via the shared
 *       {@link SubprocessLauncher} (port probe, TCP readiness, process-tree
 *       teardown).</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real go build;
 * the end-to-end launch is exercised by the orchestrated run.
 */
public final class GoLaunchPlan implements Launcher {

    /** The go executable (resolved from PATH). */
    static final String DEFAULT_GO = "go";

    /** The make executable (resolved from PATH). */
    static final String DEFAULT_MAKE = "make";

    /** The Dafny version the Go transpile uses (aws-encryption-sdk's project.properties). */
    static final String REQUIRED_DAFNY_VERSION = "4.9.0";

    /**
     * The server binary name the {@code go build} produces at
     * {@code <serverDir>/<product>-test-server}. Each SDK's Go server
     * declares the module accordingly.
     */
    private final String serverBinaryName;
    private final String product;

    private static final String SERVER_LOG_NAME = "go-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String go;
    private final String make;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     * @param product       the SDK product identifier — the Go server binary
     *                      is expected at
     *                      {@code <serverDir>/<product>-test-server}
     */
    public GoLaunchPlan(Path workDirectory, String product) {
        this(workDirectory, product, DEFAULT_GO, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier (drives the
     *                           expected binary name)
     * @param go                 the go executable
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public GoLaunchPlan(Path workDirectory, String product,
            String go, SubprocessLauncher subprocessLauncher) {
        this(workDirectory, product, go, DEFAULT_MAKE, subprocessLauncher);
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier
     * @param go                 the go executable
     * @param make               the make executable (the Dafny transpile)
     * @param subprocessLauncher the shared launch machinery
     */
    public GoLaunchPlan(Path workDirectory, String product,
            String go, String make, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
        }
        if (go == null || go.isBlank()) {
            throw new IllegalArgumentException("go is required");
        }
        if (make == null || make.isBlank()) {
            throw new IllegalArgumentException("make is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.go = go;
        this.make = make;
        this.subprocessLauncher = subprocessLauncher;
        this.serverBinaryName = product + "-test-server";
        this.product = product;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory (Req 2.5). The library is
        //    a go.mod replace target within the same clone; it is resolved only
        //    to decide whether it must be transpiled first.
        MaterializedSources.Success resolved = sources.successOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));
        Path serverDir = resolved.directory();
        Optional<Path> dafnyProject = sources.directoryOf(ComponentId.library(language))
            .flatMap(DafnyProject::of);

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2. Build: go build -o esdk-test-server . in the server directory.
        //    Skipped when the stamp shows this commit's binary is already built.
        BuildStamp stamp = new BuildStamp(serverDir, product);
        if (!stamp.upToDate(resolved.commit(), resolved.dirty(),
                List.of(serverDir.resolve(serverBinaryName)))) {
            if (dafnyProject.isPresent()) {
                transpile(language, dafnyProject.get());
            }
            runBuildStep(language, "go build -buildvcs=false -o " + serverBinaryName + " .",
                buildCommand(go, serverBinaryName), serverDir, Map.of());
            stamp.write(language, resolved.commit(), resolved.dirty());
        }

        // 3. Launch: <server>/esdk-test-server <port> from the server directory,
        //    via the shared probe/spawn/readiness/teardown.
        ProcessBuilder process = new ProcessBuilder(serverCommand(serverDir, entry.port(), serverBinaryName));
        process.directory(serverDir.toFile());
        process.redirectErrorStream(true);
        process.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), process);
    }

    /**
     * Transpile the smithy-dafny library at {@code dafnyProjectDir} and its MPL
     * dependencies in place, serialized with any other Dafny build in the clone.
     */
    private void transpile(String language, Path dafnyProjectDir) throws ServerLaunchException {
        if (!DafnyProject.commandOnPath("dafny", System.getenv("PATH"))) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "the " + language + " Language_Server build requires Dafny " + REQUIRED_DAFNY_VERSION
                    + " on PATH ('dafny' was not found): the Go library's Dafny-generated packages"
                    + " are not committed and are transpiled before building");
        }
        Path repoRoot = DafnyProject.repositoryRoot(dafnyProjectDir);
        Map<String, String> codegenEnv = DafnyProject.codegenEnvironment(
            System.getenv(DafnyProject.CODEGEN_JAVA_HOME_VARIABLE));
        synchronized (DafnyProject.lockFor(repoRoot)) {
            for (List<String> submodule : DafnyProject.submoduleCommands(repoRoot)) {
                runBuildStep(language, String.join(" ", submodule), submodule, repoRoot, Map.of());
            }
            runBuildStep(language, "make transpile (implementation + dependencies)",
                transpileCommand(make), dafnyProjectDir, codegenEnv);
        }
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without a go build).
    // ------------------------------------------------------------------

    /**
     * The {@code transpile_go} steps the server build needs, in order: the
     * extern rewrite, the MPL dependencies, the implementation, and the extern
     * restore. The library's own Dafny tests are not transpiled.
     */
    static List<String> transpileCommand(String make) {
        return List.of(make, "_no_extern_pre_transpile", "transpile_dependencies_go",
            "transpile_implementation_go", "_no_extern_post_transpile", "CORES=4");
    }

    /** {@code go build -buildvcs=false -o esdk-test-server .}. */
    static List<String> buildCommand(String go, String serverBinaryName) {
        // -buildvcs=false: the server builds from a materialized clone whose git
        // state makes Go's VCS stamping fail (git exits 128).
        return List.of(go, "build", "-buildvcs=false", "-o", serverBinaryName, ".");
    }

    /** {@code <server>/esdk-test-server <port>}. */
    static List<String> serverCommand(Path serverDir, int port, String serverBinaryName) {
        return List.of(serverDir.resolve(serverBinaryName).toString(), String.valueOf(port));
    }

    // ------------------------------------------------------------------
    // Build-step execution.
    // ------------------------------------------------------------------

    private static ServerLaunchException missingComponent(String language, ComponentId component) {
        return new ServerLaunchException(language, ServerLaunchException.Category.RESOLVE,
            "the " + language + " Language_Server launch requires the resolved '" + component
                + "' directory, but that component was not materialized for this run");
    }

    /**
     * Run the synchronous build to completion in {@code buildDir}, with
     * {@code environment} added to the inherited one. A build that
     * cannot start, is interrupted, or exits non-zero is a {@code BUILD} launch
     * failure naming the step and carrying the tool output (Req 2.5).
     */
    private void runBuildStep(String language, String step, List<String> command, Path buildDir,
            Map<String, String> environment) throws ServerLaunchException {
        Instant startedAt = Instant.now();
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(buildDir.toFile());
            builder.redirectErrorStream(true);
            builder.environment().putAll(environment);

            Process process;
            try {
                process = builder.start();
            } catch (IOException e) {
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command, e.getMessage()), e);
            }

            String output;
            int exitCode;
            try {
                output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                exitCode = process.waitFor();
            } catch (IOException e) {
                process.destroyForcibly();
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command, e.getMessage()), e);
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command, "interrupted while waiting"), e);
            }

            if (exitCode != 0) {
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command,
                        "exit code " + exitCode + "; output:\n" + tail(output)));
            }
        } finally {
            LaunchTimings.log(language, step, startedAt);
        }
    }

    private static String buildFailureMessage(String language, String step,
            List<String> command, String detail) {
        return "the " + language + " Language_Server build step '" + step
            + "' failed (" + String.join(" ", command) + "): " + detail;
    }

    private static String tail(String output) {
        String trimmed = output.strip();
        if (trimmed.length() <= MAX_FAILURE_OUTPUT_CHARS) {
            return trimmed;
        }
        return "..." + trimmed.substring(trimmed.length() - MAX_FAILURE_OUTPUT_CHARS);
    }
}
