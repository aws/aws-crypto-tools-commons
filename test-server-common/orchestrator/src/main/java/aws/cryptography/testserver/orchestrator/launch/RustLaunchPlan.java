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
 *   <li><b>Transpile the library.</b> When the library component is a
 *       smithy-dafny {@code runtimes/rust} directory ({@link DafnyProject}),
 *       its Rust code is generated, not committed: in the clone root,
 *       initialize each present Dafny submodule, then {@code make
 *       polymorph_rust} and {@code make transpile_rust CORES=4} in the
 *       library's project directory (e.g. {@code AwsEncryptionSDK/}), the steps
 *       the repository's own Rust workflow runs. The code generator runs with
 *       {@code JAVA_HOME} set to {@value #CODEGEN_JAVA_HOME_VARIABLE} when that
 *       is set. Dafny {@value #REQUIRED_DAFNY_VERSION} must be on {@code PATH};
 *       its absence is an eager {@code BUILD} failure. Any other library (a
 *       hand-written crate such as aws-crypto-tools-rust's {@code esdk}) is
 *       built directly.</li>
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

    /** The make executable (resolved from PATH). */
    static final String DEFAULT_MAKE = "make";

    /** The Dafny version the Rust transpile uses (aws-encryption-sdk's library_rust_tests.yml). */
    static final String REQUIRED_DAFNY_VERSION = "4.10.0";

    /** Names the JDK the smithy-dafny code generator runs on, when it differs from the orchestrator's. */
    static final String CODEGEN_JAVA_HOME_VARIABLE = "TESTSERVER_CODEGEN_JAVA_HOME";

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
    private final String make;
    private final SubprocessLauncher subprocessLauncher;
    private final String product;

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
        this(workDirectory, product, cargo, DEFAULT_MAKE, subprocessLauncher);
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier
     * @param cargo              the cargo executable
     * @param make               the make executable (the Dafny transpile)
     * @param subprocessLauncher the shared launch machinery
     */
    public RustLaunchPlan(Path workDirectory, String product,
            String cargo, String make, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
        }
        if (cargo == null || cargo.isBlank()) {
            throw new IllegalArgumentException("cargo is required");
        }
        if (make == null || make.isBlank()) {
            throw new IllegalArgumentException("make is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.cargo = cargo;
        this.make = make;
        this.subprocessLauncher = subprocessLauncher;
        this.serverBinaryName = product + "-test-server";
        this.product = product;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory (Req 2.5). The library
        //    crate is a cargo path dependency within the same clone; it is
        //    resolved only to decide whether it must be transpiled first.
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

        // 2. Build: cargo build --release in the server directory.
        //    Skipped when the stamp shows this commit's binary is already built.
        BuildStamp stamp = new BuildStamp(serverDir, product);
        Path binary = targetDirectory(serverDir).resolve("release").resolve(serverBinaryName);
        if (!stamp.upToDate(resolved.commit(), resolved.dirty(), List.of(binary))) {
            if (dafnyProject.isPresent()) {
                transpile(language, dafnyProject.get());
            }
            runBuildStep(language, "cargo build --release", buildCommand(cargo), serverDir, Map.of());
            stamp.write(language, resolved.commit(), resolved.dirty());
        }

        // 3. Launch: <server>/target/release/esdk-test-server <port> from the
        //    server directory, via the shared probe/spawn/readiness/teardown.
        ProcessBuilder server = new ProcessBuilder(serverCommand(serverDir, entry.port(), serverBinaryName));
        server.directory(serverDir.toFile());
        server.redirectErrorStream(true);
        server.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), server);
    }

    /**
     * Generate and transpile the smithy-dafny library at {@code dafnyProjectDir}
     * in place, serialized with any other Dafny build in the same clone.
     */
    private void transpile(String language, Path dafnyProjectDir) throws ServerLaunchException {
        if (!DafnyProject.commandOnPath("dafny", System.getenv("PATH"))) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "the " + language + " Language_Server build requires Dafny " + REQUIRED_DAFNY_VERSION
                    + " on PATH ('dafny' was not found): the Rust library carries no committed"
                    + " generated code and transpiles from Dafny before building");
        }
        Path repoRoot = DafnyProject.repositoryRoot(dafnyProjectDir);
        Map<String, String> codegenEnv = codegenEnvironment(System.getenv(CODEGEN_JAVA_HOME_VARIABLE));
        synchronized (DafnyProject.lockFor(repoRoot)) {
            for (List<String> submodule : DafnyProject.submoduleCommands(repoRoot)) {
                runBuildStep(language, String.join(" ", submodule), submodule, repoRoot, Map.of());
            }
            runBuildStep(language, "make polymorph_rust", polymorphCommand(make), dafnyProjectDir, codegenEnv);
            runBuildStep(language, "make transpile_rust", transpileCommand(make), dafnyProjectDir, codegenEnv);
        }
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without a cargo build).
    // ------------------------------------------------------------------

    /** {@code make polymorph_rust}: generates the library's Smithy Rust code. */
    static List<String> polymorphCommand(String make) {
        return List.of(make, "polymorph_rust");
    }

    /** {@code make transpile_rust CORES=4}: transpiles the library's Dafny to Rust. */
    static List<String> transpileCommand(String make) {
        return List.of(make, "transpile_rust", "CORES=4");
    }

    /** {@code JAVA_HOME} for the code generator, when {@code codegenJavaHome} is set. */
    static Map<String, String> codegenEnvironment(String codegenJavaHome) {
        return codegenJavaHome == null || codegenJavaHome.isBlank()
            ? Map.of() : Map.of("JAVA_HOME", codegenJavaHome);
    }

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
