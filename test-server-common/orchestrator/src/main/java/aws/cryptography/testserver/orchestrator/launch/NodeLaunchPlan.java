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

/**
 * The Node.js {@code Language_Server} launch plan: builds the rpcv2Cbor server
 * that ships in aws-encryption-sdk-javascript ({@code test-server/}) and
 * delegates to the real AWS Encryption SDK for JavaScript (the repository's
 * {@code modules/*} workspace packages), from the run's <em>resolved</em>
 * sources.
 *
 * <ol>
 *   <li><b>Resolve.</b> The server directory (the {@code test-server} path
 *       within the materialized aws-encryption-sdk-javascript clone) comes from
 *       the {@link MaterializedSources}; the modules the server imports resolve
 *       from the repository-root workspace in the same clone. A missing
 *       component is a {@code RESOLVE} launch failure (Requirement 2.5).</li>
 *   <li><b>Build.</b> The server Makefile's {@code build-server} recipe against
 *       a fresh clone: {@code npm ci --unsafe-perm} then {@code npm run
 *       build-node} at the repository root, then {@code npx tsc -p
 *       tsconfig.json} in the server directory. A non-zero step is a
 *       {@code BUILD} launch failure carrying the tool output. (The root
 *       {@code npm ci} runs the repository's lerna postinstall, which needs
 *       {@code structuredClone} — Node.js 17+.) A stamp file written after
 *       a successful build skips these steps when a reused clone already
 *       holds a build of the same commit.</li>
 *   <li><b>Launch.</b> {@code node <server>/build/src/main.js <port>} via the
 *       shared {@link SubprocessLauncher} (port probe, TCP readiness,
 *       process-tree teardown).</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real npm build;
 * the end-to-end launch is exercised by the orchestrated run.
 */
public final class NodeLaunchPlan implements Launcher {

    /** The npm executable (resolved from PATH). */
    static final String DEFAULT_NPM = "npm";

    /** The node executable (resolved from PATH). */
    static final String DEFAULT_NODE = "node";

    /** The compiled server entry point, relative to the server directory. */
    static final String SERVER_ENTRY = "build/src/main.js";

    /**
     * Build stamp in the server directory: holds the clone commit the last
     * successful build ran at. When it matches the resolved commit and the
     * compiled entry point exists (a reused clone), the build is skipped.
     * File name is {@code .<product>-build-stamp}.
     */
    private final String buildStampName;

    private static final String SERVER_LOG_NAME = "node-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String npm;
    private final String node;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     * @param product       the SDK product identifier — the build stamp file
     *                      is {@code .<product>-build-stamp}
     */
    public NodeLaunchPlan(Path workDirectory, String product) {
        this(workDirectory, product, DEFAULT_NPM, DEFAULT_NODE, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier (drives the
     *                           build stamp filename)
     * @param npm                the npm executable
     * @param node               the node executable
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public NodeLaunchPlan(Path workDirectory, String product, String npm, String node,
            SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
        }
        if (npm == null || npm.isBlank()) {
            throw new IllegalArgumentException("npm is required");
        }
        if (node == null || node.isBlank()) {
            throw new IllegalArgumentException("node is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.npm = npm;
        this.node = node;
        this.subprocessLauncher = subprocessLauncher;
        this.buildStampName = "." + product + "-build-stamp";
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory and its repository root
        //    (Req 2.5). The modules the server imports are workspace packages of
        //    the same clone, so only the server component is resolved here.
        MaterializedSources.Success server = sources.successOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));
        Path serverDir = server.directory();
        Path repoRoot = server.root();

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2. Build: the server Makefile's build-server recipe against a fresh
        //    clone — root npm ci + npm run build-node, then tsc in the server.
        //    Skipped when the stamp shows a successful build of this exact
        //    commit already sits in the (reused) clone.
        if (!buildUpToDate(serverDir, server.commit(), server.dirty(), buildStampName)) {
            runBuildStep(language, "npm ci --unsafe-perm", installCommand(npm), repoRoot);
            runBuildStep(language, "npm run build-node", buildModulesCommand(npm), repoRoot);
            runBuildStep(language, "npx tsc -p tsconfig.json", buildServerCommand(), serverDir);
            writeBuildStamp(language, serverDir, server.commit(), buildStampName);
        }

        // 3. Launch: node <server>/build/src/main.js <port> via the shared
        //    probe/spawn/readiness/teardown.
        ProcessBuilder process = new ProcessBuilder(serverCommand(node, serverDir, entry.port()));
        process.directory(serverDir.toFile());
        process.redirectErrorStream(true);
        process.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), process);
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without an npm build).
    // ------------------------------------------------------------------

    /** {@code npm ci --unsafe-perm} (repository root). */
    static List<String> installCommand(String npm) {
        return List.of(npm, "ci", "--unsafe-perm");
    }

    /** {@code npm run build-node} (repository root). */
    static List<String> buildModulesCommand(String npm) {
        return List.of(npm, "run", "build-node");
    }

    /** {@code npx tsc -p tsconfig.json} (server directory). */
    static List<String> buildServerCommand() {
        return List.of("npx", "tsc", "-p", "tsconfig.json");
    }

    /** {@code node <server>/build/src/main.js <port>}. */
    static List<String> serverCommand(String node, Path serverDir, int port) {
        return List.of(node, serverDir.resolve(SERVER_ENTRY).toString(), String.valueOf(port));
    }

    // ------------------------------------------------------------------
    // Build stamp (skip the build on a reused clone of the same commit).
    // ------------------------------------------------------------------

    /**
     * Whether {@code serverDir} already holds a successful build of
     * {@code commit}: the stamp records exactly that commit, the compiled
     * entry point exists, <em>and</em> the source is not modified since the
     * stamp was written. A working-tree component whose {@code dirty} flag
     * is {@code true} always forces a rebuild — commit hash alone cannot
     * capture uncommitted source edits. {@code null} dirty indicates a
     * clone component (never dirty).
     */
    static boolean buildUpToDate(Path serverDir, String commit, Boolean dirty, String buildStampName) {
        if (dirty != null && dirty) {
            return false;
        }
        Path stamp = serverDir.resolve(buildStampName);
        if (!Files.isRegularFile(stamp)
                || !Files.isRegularFile(serverDir.resolve(SERVER_ENTRY))) {
            return false;
        }
        try {
            return Files.readString(stamp, StandardCharsets.UTF_8).trim().equals(commit);
        } catch (IOException e) {
            return false;
        }
    }

    private static void writeBuildStamp(String language, Path serverDir, String commit, String buildStampName)
            throws ServerLaunchException {
        try {
            Files.writeString(serverDir.resolve(buildStampName), commit,
                StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to write the " + language + " build stamp in " + serverDir
                    + ": " + e.getMessage(), e);
        }
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
     * Run the synchronous build to completion in {@code buildDir}. A build that
     * cannot start, is interrupted, or exits non-zero is a {@code BUILD} launch
     * failure naming the step and carrying the tool output (Req 2.5).
     */
    private void runBuildStep(String language, String step, List<String> command, Path buildDir)
            throws ServerLaunchException {
        Instant startedAt = Instant.now();
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(buildDir.toFile());
            builder.redirectErrorStream(true);

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
