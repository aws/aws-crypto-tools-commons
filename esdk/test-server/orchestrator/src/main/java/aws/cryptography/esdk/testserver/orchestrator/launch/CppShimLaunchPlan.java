package aws.cryptography.esdk.testserver.orchestrator.launch;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.source.ComponentId;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The C++-shim {@code Language_Server} launch plan: builds the rpcv2Cbor server
 * that ships in aws-crypto-tools-rust ({@code esdk-cpp-test-server/}) and runs
 * every operation through the {@code aws-esdk-cpp} C++ facade, from the run's
 * <em>resolved</em> sources.
 *
 * <ol>
 *   <li><b>Resolve.</b> The server directory (the {@code esdk-cpp-test-server}
 *       path within the materialized aws-crypto-tools-rust clone) comes from the
 *       {@link MaterializedSources}; the {@code esdk/shims/aws-esdk-cpp} shim and
 *       the sibling {@code esdk} / MPL crates it depends on live in the same
 *       clone. A missing component is a {@code RESOLVE} launch failure.</li>
 *   <li><b>Build the shim.</b> {@code cargo build --release} in
 *       {@code esdk/shims/aws-esdk-cpp}; the server's cdylib link requires it.
 *       This step is built into the shim's own {@code target/} (its
 *       {@code CARGO_TARGET_DIR} is cleared) so the server's build script finds
 *       the cdylib where it looks for it.</li>
 *   <li><b>Build the server.</b> {@code cargo build --release} in the server
 *       directory. A non-zero build is a {@code BUILD} failure carrying the tool
 *       output. (The build natively compiles {@code aws-lc-sys}, which needs a
 *       Rust toolchain and Go on PATH.)</li>
 *   <li><b>Launch.</b> {@code <server>/target/release/esdk-cpp-test-server
 *       <port>} via the shared {@link SubprocessLauncher}.</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real cargo build.
 */
public final class CppShimLaunchPlan implements Launcher {

    /** The cargo executable (resolved from PATH). */
    static final String DEFAULT_CARGO = "cargo";

    /** The release binary name cargo produces. */
    static final String SERVER_BINARY_NAME = "esdk-cpp-test-server";

    /** The aws-esdk-cpp shim directory, relative to the clone root. */
    static final String SHIM_RELATIVE_PATH = "esdk/shims/aws-esdk-cpp";

    /** The default cargo target directory (relative to the server crate). */
    static final String DEFAULT_TARGET_DIR = "target";

    private static final String SERVER_LOG_NAME = "cpp-shim-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String cargo;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     */
    public CppShimLaunchPlan(Path workDirectory) {
        this(workDirectory, DEFAULT_CARGO, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param cargo              the cargo executable
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public CppShimLaunchPlan(Path workDirectory, String cargo, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (cargo == null || cargo.isBlank()) {
            throw new IllegalArgumentException("cargo is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.cargo = cargo;
        this.subprocessLauncher = subprocessLauncher;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory. The shim and the library
        //    crate are within the same clone, so only the server component is
        //    resolved here.
        Path serverDir = sources.directoryOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));
        Path shimDir = serverDir.getParent().resolve(SHIM_RELATIVE_PATH);
        if (!Files.isDirectory(shimDir)) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.RESOLVE,
                "the " + language + " Language_Server launch requires the aws-esdk-cpp shim at "
                    + shimDir + ", but that directory is not present in the resolved sources");
        }

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2. Build the shim into its own target/ (CARGO_TARGET_DIR cleared) so the
        //    server's build script finds the cdylib where it looks for it.
        runBuildStep(language, "cargo build --release (aws-esdk-cpp shim)",
            buildCommand(cargo), shimDir, true);

        // 3. Build the server.
        runBuildStep(language, "cargo build --release", buildCommand(cargo), serverDir, false);

        // 4. Launch: <server>/target/release/esdk-cpp-test-server <port> via the
        //    shared probe/spawn/readiness/teardown.
        ProcessBuilder server = new ProcessBuilder(serverCommand(serverDir, entry.port()));
        server.directory(serverDir.toFile());
        server.redirectErrorStream(true);
        server.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), server);
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without a cargo build).
    // ------------------------------------------------------------------

    /** {@code cargo build --release}. */
    static List<String> buildCommand(String cargo) {
        return List.of(cargo, "build", "--release");
    }

    /** {@code <target>/release/esdk-cpp-test-server <port>}. */
    static List<String> serverCommand(Path serverDir, int port) {
        Path binary = targetDirectory(serverDir).resolve("release").resolve(SERVER_BINARY_NAME);
        return List.of(binary.toString(), String.valueOf(port));
    }

    /**
     * The cargo target directory: {@code CARGO_TARGET_DIR} when set in the
     * environment (an absolute value is used as-is; a relative one is resolved
     * against the server crate, as cargo does since the build runs there),
     * otherwise {@code <server>/target}.
     */
    static Path targetDirectory(Path serverDir) {
        String configured = System.getenv("CARGO_TARGET_DIR");
        if (configured != null && !configured.isBlank()) {
            return serverDir.resolve(configured);
        }
        return serverDir.resolve(DEFAULT_TARGET_DIR);
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
     * failure naming the step and carrying the tool output. When
     * {@code clearCargoTargetDir} is set, {@code CARGO_TARGET_DIR} is removed
     * from the step's environment so the output lands in {@code buildDir/target}.
     */
    private void runBuildStep(String language, String step, List<String> command, Path buildDir,
            boolean clearCargoTargetDir) throws ServerLaunchException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(buildDir.toFile());
        builder.redirectErrorStream(true);
        if (clearCargoTargetDir) {
            builder.environment().remove("CARGO_TARGET_DIR");
        }

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
