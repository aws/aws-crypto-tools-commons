package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The Rust {@code Language_Server} launch plan (Requirements 1.5, 2.1, 2.7):
 * builds the hand-rolled rpcv2Cbor server that ships in aws-crypto-tools-rust
 * ({@code esdk-test-server/}) and delegates to the real AWS Encryption SDK for
 * Rust ({@code aws-esdk}), from the run's <em>resolved</em> sources.
 *
 * <ol>
 *   <li><b>Resolve.</b> The Rust server directory (the {@code esdk-test-server}
 *       path within the materialized aws-crypto-tools-rust clone) comes from the
 *       {@link MaterializedSources}; the sibling {@code esdk} / MPL crates the
 *       server's cargo path dependencies point at are present in the same clone.
 *       A missing component is a {@code RESOLVE} launch failure (Requirement
 *       2.5).</li>
 *   <li><b>Build.</b> {@code cargo build --release} in the server directory. A
 *       non-zero build is a {@code BUILD} launch failure carrying the tool
 *       output. (The build fetches crates and natively compiles {@code
 *       aws-lc-sys}, which needs a Rust toolchain and Go on PATH.)</li>
 *   <li><b>Launch.</b> {@code <server>/target/release/esdk-test-server <port>}
 *       via the shared {@link SubprocessLauncher} (port probe, TCP readiness,
 *       process-tree teardown).</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real cargo build;
 * the end-to-end launch is exercised by the orchestrated run.
 */
public final class RustLaunchPlan implements Launcher {

    /** The cargo executable (resolved from PATH). */
    static final String DEFAULT_CARGO = "cargo";

    /** The release binary name cargo produces. */
    /**
     * The binary name the cargo release build produces at
     * {@code <serverDir>/target/release/}: {@code <product>-test-server}. Each
     * SDK's Rust {@code Cargo.toml} names the crate accordingly.
     */
    private final String serverBinaryName;

    /** The default cargo target directory (relative to the server crate). */
    static final String DEFAULT_TARGET_DIR = "target";

    private static final String SERVER_LOG_NAME = "rust-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String cargo;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     * @param product       the SDK product identifier — the Rust server
     *                      binary is expected at
     *                      {@code target/release/<product>-test-server}
     */
    public RustLaunchPlan(Path workDirectory, String product) {
        this(workDirectory, product, DEFAULT_CARGO, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier (drives the
     *                           expected binary name)
     * @param cargo              the cargo executable
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public RustLaunchPlan(Path workDirectory, String product,
            String cargo, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
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
        this.serverBinaryName = product + "-test-server";
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory (Req 2.5). The library
        //    crate is a cargo path dependency within the same clone, so only the
        //    server component is resolved here.
        Path serverDir = sources.directoryOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2. Build: cargo build --release in the server directory.
        runBuildStep(language, "cargo build --release", buildCommand(cargo), serverDir);

        // 3. Launch: <server>/target/release/esdk-test-server <port> from the
        //    server directory, via the shared probe/spawn/readiness/teardown.
        ProcessBuilder server = new ProcessBuilder(serverCommand(serverDir, entry.port(), serverBinaryName));
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

    /** {@code <target>/release/esdk-test-server <port>}. */
    static List<String> serverCommand(Path serverDir, int port, String serverBinaryName) {
        Path binary = targetDirectory(serverDir).resolve("release").resolve(serverBinaryName);
        return List.of(binary.toString(), String.valueOf(port));
    }

    /**
     * The cargo target directory: {@code CARGO_TARGET_DIR} when set in the
     * environment (an absolute value is used as-is; a relative one is resolved
     * against the server crate, as cargo does since the build runs there),
     * otherwise {@code <server>/target}. Honoring the env var lets CI point the
     * build at a stable, cached location instead of the ephemeral clone.
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
     * Run the synchronous build to completion in {@code serverDir}. A build that
     * cannot start, is interrupted, or exits non-zero is a {@code BUILD} launch
     * failure naming the step and carrying the tool output (Req 2.5).
     */
    private void runBuildStep(String language, String step, List<String> command, Path serverDir)
            throws ServerLaunchException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(serverDir.toFile());
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
