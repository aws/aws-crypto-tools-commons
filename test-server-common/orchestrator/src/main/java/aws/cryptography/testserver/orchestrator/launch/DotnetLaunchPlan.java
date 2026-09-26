package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * The .NET {@code Language_Server} launch plan: builds the rpcv2Cbor server
 * that ships in aws-encryption-sdk ({@code esdk-test-servers/net/}) and
 * delegates to the real AWS Encryption SDK for .NET
 * ({@code AwsEncryptionSDK/runtimes/net}, a project reference), from the run's
 * <em>resolved</em> sources.
 *
 * <p>The .NET library carries no committed generated code — it transpiles from
 * Dafny — so the build reproduces the repository's own net pipeline before the
 * server compiles:
 *
 * <ol>
 *   <li><b>Resolve.</b> The server directory (the {@code esdk-test-servers/net}
 *       path within the materialized aws-encryption-sdk clone) comes from the
 *       {@link MaterializedSources}. A missing component is a {@code RESOLVE}
 *       launch failure (Requirement 2.5). A {@code dafny} executable absent
 *       from {@code PATH} is an eager {@code BUILD} failure naming the
 *       requirement (Dafny {@value #REQUIRED_DAFNY_VERSION}), before any make
 *       step runs.</li>
 *   <li><b>Transpile the library.</b> In the clone root: {@code git submodule
 *       update --init libraries} and {@code git submodule update --init
 *       --recursive mpl} (the transpile targets live in the mpl submodule's
 *       smithy-dafny makefile), then {@code make setup_net} and {@code make
 *       transpile_net CORES=4} in {@code AwsEncryptionSDK/} — the same steps
 *       the repository's own net workflow runs. A non-zero step is a
 *       {@code BUILD} launch failure carrying the tool output. A stamp file
 *       written after a successful build skips the transpile and build steps
 *       (Dafny gate included) when a reused clone already holds a build of
 *       the same commit.</li>
 *   <li><b>Build the server.</b> The server Makefile's {@code build-server}
 *       recipe: {@code dotnet build EsdkTestServer.csproj -c Release} in the
 *       server directory.</li>
 *   <li><b>Launch.</b> {@code dotnet <server>/bin/Release/net8.0/
 *       EsdkTestServer.dll <port>} via the shared {@link SubprocessLauncher}
 *       (port probe, TCP readiness, process-tree teardown).</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real Dafny
 * transpile; the end-to-end launch is exercised by the orchestrated run.
 */
public final class DotnetLaunchPlan implements Launcher {

    /** The dotnet executable (resolved from PATH). */
    static final String DEFAULT_DOTNET = "dotnet";

    /** The make executable (resolved from PATH). */
    static final String DEFAULT_MAKE = "make";

    /** The Dafny version the repository's transpile pins (project.properties). */
    static final String REQUIRED_DAFNY_VERSION = "4.9.0";

    /** The Dafny build directory, relative to the clone root. */
    static final String DAFNY_PROJECT_RELATIVE_PATH = "AwsEncryptionSDK";

    /**
     * Server csproj filename, resolved in the server directory. Derived from
     * {@code product}: {@code <Product>TestServer.csproj} (title-cased),
     * matching the sibling repos' convention (ESDK ships
     * {@code EsdkTestServer.csproj}, DB-ESDK ships {@code DbesdkTestServer.csproj}).
     */
    private final String csprojName;

    /**
     * Built server assembly relative to the server directory. Derived from
     * {@code product}: {@code bin/Release/net8.0/<Product>TestServer.dll}.
     */
    private final String serverDllRelativePath;

    /**
     * Build stamp in the server directory: holds the clone commit the last
     * successful build ran at. When it matches the resolved commit and the
     * built assembly exists (a reused clone), the transpile and build are
     * skipped. File name is {@code .<product>-build-stamp}.
     */
    private final String buildStampName;

    private static final String SERVER_LOG_NAME = "net-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String dotnet;
    private final String make;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     * @param product       the SDK product identifier — drives the csproj
     *                      filename, DLL path, and build-stamp name
     */
    public DotnetLaunchPlan(Path workDirectory, String product) {
        this(workDirectory, product, DEFAULT_DOTNET, DEFAULT_MAKE, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier (drives csproj,
     *                           DLL, and build-stamp names)
     * @param dotnet             the dotnet executable
     * @param make               the make executable
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public DotnetLaunchPlan(Path workDirectory, String product, String dotnet, String make,
            SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
        }
        if (dotnet == null || dotnet.isBlank()) {
            throw new IllegalArgumentException("dotnet is required");
        }
        if (make == null || make.isBlank()) {
            throw new IllegalArgumentException("make is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.dotnet = dotnet;
        this.make = make;
        this.subprocessLauncher = subprocessLauncher;
        String titleCased = Character.toUpperCase(product.charAt(0)) + product.substring(1);
        this.csprojName = titleCased + "TestServer.csproj";
        this.serverDllRelativePath = "bin/Release/net8.0/" + titleCased + "TestServer.dll";
        this.buildStampName = "." + product + "-build-stamp";
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized server directory and its repository root
        //    (Req 2.5); the library transpiles within the same clone.
        MaterializedSources.Success server = sources.successOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));
        Path serverDir = server.directory();
        Path repoRoot = server.root();
        Path dafnyProjectDir = repoRoot.resolve(DAFNY_PROJECT_RELATIVE_PATH);

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2–3. Transpile the library and build the server. When the clone
        //    holds a Dafny transpile project (AwsEncryptionSDK/Makefile — the
        //    ESDK layout: no committed generated .NET code, transpiled from
        //    Dafny before build), run submodules + setup_net + transpile_net
        //    in the Dafny project directory before dotnet build. When it does
        //    not (DB-ESDK layout: server consumes a published NuGet DBE
        //    distribution directly), skip those steps and go straight to
        //    dotnet build.
        //
        //    All build steps are Dafny-gated: skipped when the stamp shows a
        //    successful build of this exact commit already sits in the
        //    (reused) clone.
        boolean transpileFromDafny = Files.isRegularFile(
            dafnyProjectDir.resolve("Makefile"));
        if (!buildUpToDate(serverDir, server.commit(), server.dirty(),
                buildStampName, serverDllRelativePath)) {
            if (transpileFromDafny) {
                // The transpile cannot succeed without Dafny; fail eagerly
                // with the requirement rather than deep inside make output.
                if (!commandOnPath("dafny", System.getenv("PATH"))) {
                    throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                        "the " + language + " Language_Server build requires Dafny "
                            + REQUIRED_DAFNY_VERSION + " on PATH ('dafny' was not found): the .NET"
                            + " library carries no committed generated code and transpiles from Dafny"
                            + " before building");
                }
                runBuildStep(language, "git submodule update --init libraries",
                    submoduleLibrariesCommand(), repoRoot);
                runBuildStep(language, "git submodule update --init --recursive mpl",
                    submoduleMplCommand(), repoRoot);
                runBuildStep(language, "make setup_net", setupCommand(make), dafnyProjectDir);
                runBuildStep(language, "make transpile_net", transpileCommand(make), dafnyProjectDir);
            }
            runBuildStep(language, "dotnet build " + csprojName + " -c Release",
                buildCommand(dotnet, csprojName), serverDir);
            writeBuildStamp(language, serverDir, server.commit(), buildStampName);
        }

        // 4. Launch: dotnet <server>/bin/Release/net8.0/<Product>TestServer.dll
        //    <port> via the shared probe/spawn/readiness/teardown.
        ProcessBuilder process = new ProcessBuilder(serverCommand(dotnet, serverDir, entry.port(), serverDllRelativePath));
        process.directory(serverDir.toFile());
        process.redirectErrorStream(true);
        process.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), process);
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without a Dafny transpile).
    // ------------------------------------------------------------------

    /** {@code git submodule update --init --depth 1 libraries} (clone root). */
    static List<String> submoduleLibrariesCommand() {
        return List.of("git", "submodule", "update", "--init", "--depth", "1", "libraries");
    }

    /**
     * {@code git submodule update --init --recursive --depth 1 --jobs 8 mpl}
     * (clone root). The build reads only the pinned commits' trees.
     */
    static List<String> submoduleMplCommand() {
        return List.of("git", "submodule", "update", "--init", "--recursive",
            "--depth", "1", "--jobs", "8", "mpl");
    }

    /** {@code make setup_net} (AwsEncryptionSDK/). */
    static List<String> setupCommand(String make) {
        return List.of(make, "setup_net");
    }

    /** {@code make transpile_net CORES=4} (AwsEncryptionSDK/). */
    static List<String> transpileCommand(String make) {
        return List.of(make, "transpile_net", "CORES=4");
    }

    /** {@code dotnet build <csproj> -c Release} (server directory). */
    static List<String> buildCommand(String dotnet, String csprojName) {
        return List.of(dotnet, "build", csprojName, "-c", "Release");
    }

    /** {@code dotnet <server>/<serverDllRelativePath> <port>}. */
    static List<String> serverCommand(String dotnet, Path serverDir, int port, String serverDllRelativePath) {
        return List.of(dotnet, serverDir.resolve(serverDllRelativePath).toString(),
            String.valueOf(port));
    }

    // ------------------------------------------------------------------
    // Build stamp (skip the build on a reused clone of the same commit).
    // ------------------------------------------------------------------

    /**
     * Whether {@code serverDir} already holds a successful build of
     * {@code commit}: the stamp records exactly that commit, the built
     * assembly exists, <em>and</em> the source is not modified since the
     * stamp was written. A working-tree component whose {@code dirty} flag
     * is {@code true} always forces a rebuild — commit hash alone cannot
     * capture uncommitted source edits, so a stale build would otherwise
     * run against outdated bytes and silently produce wrong results.
     * {@code null} dirty indicates a clone component (never dirty).
     */
    static boolean buildUpToDate(Path serverDir, String commit, Boolean dirty,
            String buildStampName, String serverDllRelativePath) {
        if (dirty != null && dirty) {
            return false;
        }
        Path stamp = serverDir.resolve(buildStampName);
        if (!Files.isRegularFile(stamp)
                || !Files.isRegularFile(serverDir.resolve(serverDllRelativePath))) {
            return false;
        }
        try {
            return Files.readString(stamp, StandardCharsets.UTF_8).trim().equals(commit);
        } catch (IOException e) {
            return false;
        }
    }

    private static void writeBuildStamp(String language, Path serverDir, String commit,
            String buildStampName)
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

    /**
     * Whether an executable named {@code command} exists on {@code pathValue}
     * (a {@code PATH}-style separated list of directories). Pure over its
     * inputs so the dafny gate is unit-testable with a constructed PATH.
     */
    static boolean commandOnPath(String command, String pathValue) {
        if (pathValue == null || pathValue.isBlank()) {
            return false;
        }
        for (String dir : pathValue.split(File.pathSeparator)) {
            if (dir.isBlank()) {
                continue;
            }
            Path candidate = Path.of(dir).resolve(command);
            if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return true;
            }
        }
        return false;
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
