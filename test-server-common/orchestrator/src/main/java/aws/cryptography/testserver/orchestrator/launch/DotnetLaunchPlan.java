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
import java.util.Optional;

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
 *   <li><b>Transpile the library.</b> When the library component is a
 *       smithy-dafny {@code runtimes/net} directory ({@link DafnyProject}):
 *       in the clone root, {@code git submodule update --init --recursive}
 *       each present Dafny submodule ({@code libraries}, {@code smithy-dafny},
 *       {@code mpl}), then {@code make setup_net} and {@code make
 *       transpile_net CORES=4} in the library's project directory (e.g.
 *       {@code AwsEncryptionSDK/}) — the same steps the repository's own net
 *       workflow runs. A non-zero step is a
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

    /** Repository paths, besides the Dafny project, whose content determines the transpile output. */
    static final List<String> TRANSPILE_SHARED_INPUTS =
        List.of("SharedMakefileV2.mk", "libraries", "smithy-dafny", "mpl");

    /** A file the transpile writes, relative to the Dafny project. */
    static final String TRANSPILED_FILE = "runtimes/net/ImplementationFromDafny.cs";

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
    private final String product;
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
        this.product = product;
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
        Optional<Path> dafnyProject = sources.directoryOf(ComponentId.library(language))
            .flatMap(DafnyProject::of);

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2–3. Transpile the library and build the server. A library that is
        //    a smithy-dafny runtimes/net directory has no committed generated
        //    .NET code, so run submodules + setup_net + transpile_net in its
        //    project directory before dotnet build. Any other library (e.g. a
        //    published NuGet distribution) goes straight to dotnet build.
        //
        //    All build steps are Dafny-gated: skipped when the stamp shows a
        //    successful build of this exact commit already sits in the
        //    (reused) clone.
        if (!buildUpToDate(serverDir, server.commit(), server.dirty(),
                buildStampName, serverDllRelativePath)) {
            if (dafnyProject.isPresent()) {
                Path dafnyProjectDir = dafnyProject.get();
                Path repoRoot = DafnyProject.repositoryRoot(dafnyProjectDir);
                // The transpile cannot succeed without Dafny; fail eagerly
                // with the requirement rather than deep inside make output.
                if (!DafnyProject.commandOnPath("dafny", System.getenv("PATH"))) {
                    throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                        "the " + language + " Language_Server build requires Dafny "
                            + REQUIRED_DAFNY_VERSION + " on PATH ('dafny' was not found): the .NET"
                            + " library carries no committed generated code and transpiles from Dafny"
                            + " before building");
                }
                synchronized (DafnyProject.lockFor(repoRoot)) {
                    for (List<String> submodule : DafnyProject.submoduleCommands(repoRoot)) {
                        runBuildStep(language, String.join(" ", submodule), submodule, repoRoot);
                    }
                    runBuildStep(language, "make setup_net", setupCommand(make), dafnyProjectDir);
                    // The transpile output depends only on the Dafny sources, the
                    // submodules, and the shared Makefile, so it is skipped when
                    // its stamp records those same inputs (e.g. a test-server-only
                    // change on the branch).
                    String transpileInputs = transpileInputs(repoRoot, dafnyProjectDir);
                    BuildStamp transpileStamp = new BuildStamp(dafnyProjectDir, product + "-transpile");
                    if (!transpileStamp.upToDate(transpileInputs, server.dirty(),
                            List.of(dafnyProjectDir.resolve(TRANSPILED_FILE)))) {
                        runBuildStep(language, "make transpile (implementation + dependencies)",
                            transpileCommand(make), dafnyProjectDir);
                        transpileStamp.write(language, transpileInputs, server.dirty());
                    }
                }
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

    /** {@code make setup_net} (AwsEncryptionSDK/). */
    static List<String> setupCommand(String make) {
        return List.of(make, "setup_net");
    }

    /**
     * The {@code transpile_net} steps the server build needs, in order:
     * {@code make _with_extern_pre_transpile transpile_implementation_net
     * transpile_dependencies_net _with_extern_post_transpile CORES=4}
     * (AwsEncryptionSDK/). The library's own Dafny tests are not transpiled.
     */
    static List<String> transpileCommand(String make) {
        return List.of(make, "_with_extern_pre_transpile", "transpile_implementation_net",
            "transpile_dependencies_net", "_with_extern_post_transpile", "CORES=4");
    }

    /**
     * The transpile inputs as recorded in the clone's {@code HEAD}: the tree,
     * submodule, and blob ids of the Dafny project and
     * {@link #TRANSPILE_SHARED_INPUTS}, plus the Dafny version. {@code null}
     * (never up to date) when git cannot list them.
     */
    static String transpileInputs(Path repoRoot, Path dafnyProjectDir) {
        List<String> command = new ArrayList<>(List.of("git", "ls-tree", "HEAD",
            repoRoot.relativize(dafnyProjectDir).toString()));
        command.addAll(TRANSPILE_SHARED_INPUTS);
        try {
            Process process = new ProcessBuilder(command).directory(repoRoot.toFile())
                .redirectErrorStream(true).start();
            String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8).trim();
            return process.waitFor() == 0 && !output.isEmpty()
                ? "dafny " + REQUIRED_DAFNY_VERSION + "\n" + output : null;
        } catch (IOException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
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
