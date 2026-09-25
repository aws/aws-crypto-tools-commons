package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * The C {@code Language_Server} launch plan: builds the rpcv2Cbor server that
 * ships in aws-encryption-sdk-c ({@code test-server/}) and delegates to the
 * real in-tree AWS Encryption SDK for C, from the run's <em>resolved</em>
 * sources.
 *
 * <ol>
 *   <li><b>Resolve.</b> The server directory (the {@code test-server} path
 *       within the materialized aws-encryption-sdk-c clone) comes from the
 *       {@link MaterializedSources}; the C library it links is the same clone's
 *       root CMake tree. A missing component is a {@code RESOLVE} launch
 *       failure (Requirement 2.5).</li>
 *   <li><b>Configure + build.</b> The server Makefile's recipes: {@code cmake
 *       -S <repo root> -B <server>/.build -DBUILD_TEST_SERVER=ON
 *       -DBUILD_AWS_ENC_SDK_CPP=OFF} (plus {@code -DCMAKE_PREFIX_PATH=...} when
 *       the {@code CMAKE_PREFIX_PATH} environment variable is set — how a
 *       non-standard aws-c-common install reaches the configure), then
 *       {@code cmake --build <.build> --target esdk-test-server -- -j}. A
 *       non-zero step is a {@code BUILD} launch failure carrying the tool
 *       output.</li>
 *   <li><b>Launch.</b> {@code <.build>/test-server/esdk-test-server <port>} via
 *       the shared {@link SubprocessLauncher} (port probe, TCP readiness,
 *       process-tree teardown).</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real cmake build;
 * the end-to-end launch is exercised by the orchestrated run.
 */
public final class CLaunchPlan implements Launcher {

    /** The cmake executable (resolved from PATH). */
    static final String DEFAULT_CMAKE = "cmake";

    /** The cmake build tree, relative to the server directory. */
    static final String BUILD_DIR = ".build";

    /**
     * The server binary within the build tree, at
     * {@code test-server/<product>-test-server}. The {@code test-server/}
     * subdirectory is a shared cmake convention; the binary basename varies
     * by product (each SDK's CMake target names it accordingly).
     */
    private final String serverBinaryRelativePath;

    private static final String SERVER_LOG_NAME = "c-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String cmake;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     * @param product       the SDK product identifier — the C server binary
     *                      is expected at
     *                      {@code <buildDir>/test-server/<product>-test-server}
     */
    public CLaunchPlan(Path workDirectory, String product) {
        this(workDirectory, product, DEFAULT_CMAKE, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier (drives the
     *                           expected binary name)
     * @param cmake              the cmake executable
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public CLaunchPlan(Path workDirectory, String product,
            String cmake, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
        }
        if (cmake == null || cmake.isBlank()) {
            throw new IllegalArgumentException("cmake is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.cmake = cmake;
        this.subprocessLauncher = subprocessLauncher;
        this.serverBinaryRelativePath = "test-server/" + product + "-test-server";
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory and its repository root
        //    (Req 2.5). The C library is the same clone's root CMake tree, so
        //    only the server component is resolved here.
        MaterializedSources.Success server = sources.successOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));
        Path serverDir = server.directory();
        Path repoRoot = server.root();
        Path buildDir = serverDir.resolve(BUILD_DIR);

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2. Configure + build: the server Makefile's configure and build-server
        //    recipes, with the ambient CMAKE_PREFIX_PATH passed through.
        runBuildStep(language, "cmake configure (BUILD_TEST_SERVER=ON)",
            configureCommand(cmake, repoRoot, buildDir, System.getenv("CMAKE_PREFIX_PATH")),
            serverDir);
        runBuildStep(language, "cmake --build --target esdk-test-server",
            buildCommand(cmake, buildDir), serverDir);

        // 3. Launch: <.build>/test-server/esdk-test-server <port> via the shared
        //    probe/spawn/readiness/teardown.
        ProcessBuilder process = new ProcessBuilder(serverCommand(buildDir, entry.port(), serverBinaryRelativePath));
        process.directory(serverDir.toFile());
        process.redirectErrorStream(true);
        process.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), process);
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without a cmake build).
    // ------------------------------------------------------------------

    /**
     * {@code cmake -S <repo root> -B <build dir> -DBUILD_TEST_SERVER=ON
     * -DBUILD_AWS_ENC_SDK_CPP=OFF [-DCMAKE_PREFIX_PATH=<prefix path>]}. The
     * prefix path is appended only when non-blank (the Makefile's
     * {@code CMAKE_PREFIX_PATH} pass-through).
     */
    static List<String> configureCommand(String cmake, Path repoRoot, Path buildDir,
            String cmakePrefixPath) {
        List<String> command = new ArrayList<>(List.of(
            cmake, "-S", repoRoot.toString(), "-B", buildDir.toString(),
            "-DBUILD_TEST_SERVER=ON", "-DBUILD_AWS_ENC_SDK_CPP=OFF"));
        if (cmakePrefixPath != null && !cmakePrefixPath.isBlank()) {
            command.add("-DCMAKE_PREFIX_PATH=" + cmakePrefixPath);
        }
        return List.copyOf(command);
    }

    /** {@code cmake --build <build dir> --target esdk-test-server -- -j}. */
    static List<String> buildCommand(String cmake, Path buildDir) {
        return List.of(cmake, "--build", buildDir.toString(),
            "--target", "esdk-test-server", "--", "-j");
    }

    /** {@code <build dir>/test-server/esdk-test-server <port>}. */
    static List<String> serverCommand(Path buildDir, int port, String serverBinaryRelativePath) {
        return List.of(buildDir.resolve(serverBinaryRelativePath).toString(),
            String.valueOf(port));
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
