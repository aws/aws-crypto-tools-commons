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
import java.util.Optional;

/**
 * The Python {@code Language_Server} launch plan. Builds and launches the
 * Python server entirely from the run's <em>resolved</em> sources:
 *
 * <ol>
 *   <li><b>Resolve.</b> The Python library directory (the materialized
 *       {@code aws-encryption-sdk-python} clone) and the Python server
 *       directory (the resolved {@code test-server} in
 *       {@code aws-encryption-sdk-python}) come from the
 *       {@link MaterializedSources}; a missing component is a {@code RESOLVE}
 *       launch failure.</li>
 *   <li><b>Environment.</b> Create a venv in this
 *       plan's work directory (skipped when its python already exists),
 *       upgrade pip, then a single editable install of the resolved library,
 *       the Material Providers Library (the pinned version range), cbor2 (the
 *       wire-protocol codec the server package declares), and the server
 *       package. When the resolved library is a smithy-dafny
 *       {@code runtimes/python} directory ({@link DafnyProject}), the plan
 *       first initializes the clone's Dafny submodules and runs
 *       {@code make transpile_python CORES=4} in its project directory, and
 *       installs the library without the pinned Material Providers Library:
 *       its {@code pyproject.toml} path dependencies install the sibling
 *       Dafny runtimes from the same clone. Any failing step is a {@code BUILD} launch failure naming the
 *       step and carrying the tool output.</li>
 *   <li><b>Launch.</b> {@code <venv python> -m
 *       <product>_test_server <port>} from the server directory, via the shared
 *       {@link SubprocessLauncher} (port probe, TCP readiness, process-tree
 *       teardown).</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real venv/pip;
 * the end-to-end launch is exercised by the orchestrated run.
 */
public final class PythonLaunchPlan implements Launcher {

    /**
     * The Material Providers Library requirement, exactly as the Makefile's
     * {@code setup-python} pins it.
     */
    static final String MPL_REQUIREMENT = "aws-cryptographic-material-providers>=1.7.4,<=1.11.2";

    /**
     * The wire-protocol codec, mirroring the server package's declared
     * {@code cbor2>=5.6} dependency (installed explicitly per the
     * launch-plan contract).
     */
    static final String CBOR2_REQUIREMENT = "cbor2>=5.6";

    /** The interpreter used to create the venv (the Makefile's {@code PYTHON3 ?= python3}). */
    static final String DEFAULT_PYTHON3 = "python3";

    private static final String VENV_DIR_NAME = "venv";
    private static final String SERVER_LOG_NAME = "python-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String serverModule;
    private final String python3;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      venv and the server log
     * @param product       the SDK product identifier — the server module is
     *                      {@code <product>_test_server}
     */
    public PythonLaunchPlan(Path workDirectory, String product) {
        this(workDirectory, product, DEFAULT_PYTHON3, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param product            the SDK product identifier
     * @param python3            the interpreter used to create the venv
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public PythonLaunchPlan(Path workDirectory, String product, String python3,
            SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (product == null || product.isBlank()) {
            throw new IllegalArgumentException("product is required");
        }
        if (python3 == null || python3.isBlank()) {
            throw new IllegalArgumentException("python3 is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.serverModule = product + "_test_server";
        this.python3 = python3;
        this.subprocessLauncher = subprocessLauncher;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized library + server directories.
        MaterializedSources.Success library = sources.successOf(ComponentId.library(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.library(language)));
        MaterializedSources.Success serverSource = sources.successOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));
        Path libraryDir = library.directory();
        Path serverDir = serverSource.directory();

        // 2. Environment: venv + editable installs (the Makefile's setup-python).
        Path venvDir = venvDirectory(workDirectory);
        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }
        //    Skipped when the stamp shows the venv already holds editable
        //    installs of these library and server commits.
        BuildStamp stamp = new BuildStamp(venvDir, "venv");
        String commits = library.commit() == null || serverSource.commit() == null
            ? null : library.commit() + " " + serverSource.commit();
        boolean dirty = Boolean.TRUE.equals(library.dirty()) || Boolean.TRUE.equals(serverSource.dirty());
        if (!stamp.upToDate(commits, dirty, List.of(venvPython(venvDir)))) {
            if (!Files.isExecutable(venvPython(venvDir))) {
                runSetupStep(language, "create venv", createVenvCommand(python3, venvDir));
            }
            runSetupStep(language, "upgrade pip", upgradePipCommand(venvDir));
            Optional<Path> dafnyProject = DafnyProject.of(libraryDir);
            if (dafnyProject.isPresent()) {
                if (!DafnyProject.commandOnPath("dafny", System.getenv("PATH"))) {
                    throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                        "the " + language + " Language_Server build requires Dafny on PATH ('dafny'"
                            + " was not found): the Python library transpiles from Dafny before install");
                }
                Path repoRoot = DafnyProject.repositoryRoot(dafnyProject.get());
                synchronized (DafnyProject.lockFor(repoRoot)) {
                    for (List<String> submodule : DafnyProject.submoduleCommands(repoRoot)) {
                        runSetupStep(language, String.join(" ", submodule), submodule, repoRoot);
                    }
                    runSetupStep(language, "make transpile_python", transpileCommand(), dafnyProject.get());
                }
                runSetupStep(language, "pip install library + cbor2 + server",
                    dafnyPipInstallCommand(venvDir, libraryDir, serverDir));
            } else {
                runSetupStep(language, "pip install library + MPL + cbor2 + server",
                    pipInstallCommand(venvDir, libraryDir, serverDir));
            }
            stamp.write(language, commits, dirty);
        }

        // 3. Launch: <venv python> -m <product>_test_server <port> from the server
        //    directory (the Makefile's run-python-server), via the shared
        //    probe/spawn/readiness/teardown machinery.
        ProcessBuilder server = new ProcessBuilder(serverCommand(venvDir, serverModule, entry.port()));
        server.directory(serverDir.toFile());
        server.redirectErrorStream(true);
        server.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), server);
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without venv/pip).
    // ------------------------------------------------------------------

    /** The venv location within a plan's work directory. */
    static Path venvDirectory(Path workDirectory) {
        return workDirectory.resolve(VENV_DIR_NAME);
    }

    /** The venv's python interpreter ({@code <venv>/bin/python}). */
    static Path venvPython(Path venvDir) {
        return venvDir.resolve("bin").resolve("python");
    }

    /** The venv's pip ({@code <venv>/bin/pip}). */
    static Path venvPip(Path venvDir) {
        return venvDir.resolve("bin").resolve("pip");
    }

    /** {@code python3 -m venv <venvDir>} (the Makefile's venv creation). */
    static List<String> createVenvCommand(String python3, Path venvDir) {
        return List.of(python3, "-m", "venv", venvDir.toString());
    }

    /** {@code <venv>/bin/pip install --quiet --upgrade pip}. */
    static List<String> upgradePipCommand(Path venvDir) {
        return List.of(venvPip(venvDir).toString(), "install", "--quiet", "--upgrade", "pip");
    }

    /**
     * The single editable install, in the Makefile's order with the resolved
     * library substituted for the {@code .deps} clone: {@code pip install
     * --quiet -e <library> <MPL> <cbor2> -e <server>}.
     */
    static List<String> pipInstallCommand(Path venvDir, Path libraryDir, Path serverDir) {
        return List.of(venvPip(venvDir).toString(), "install", "--quiet",
            "-e", libraryDir.toString(),
            MPL_REQUIREMENT,
            CBOR2_REQUIREMENT,
            "-e", serverDir.toString());
    }

    /** {@code make transpile_python CORES=4} (the smithy-dafny project directory). */
    static List<String> transpileCommand() {
        return List.of("make", "transpile_python", "CORES=4");
    }

    /**
     * {@code pip install --quiet -e <library> <cbor2> -e <server>}: a
     * smithy-dafny runtime brings its sibling runtimes as path dependencies,
     * so the pinned Material Providers Library is omitted.
     */
    static List<String> dafnyPipInstallCommand(Path venvDir, Path libraryDir, Path serverDir) {
        return List.of(venvPip(venvDir).toString(), "install", "--quiet",
            "-e", libraryDir.toString(),
            CBOR2_REQUIREMENT,
            "-e", serverDir.toString());
    }

    /** {@code <venv python> -m <module> <port>}. */
    static List<String> serverCommand(Path venvDir, String module, int port) {
        return List.of(venvPython(venvDir).toString(), "-m", module, String.valueOf(port));
    }

    // ------------------------------------------------------------------
    // Setup-step execution.
    // ------------------------------------------------------------------

    private static ServerLaunchException missingComponent(String language, ComponentId component) {
        return new ServerLaunchException(language, ServerLaunchException.Category.RESOLVE,
            "the " + language + " Language_Server launch requires the resolved '" + component
                + "' directory, but that component was not materialized for this run");
    }

    /**
     * Run one synchronous environment-preparation step to completion. A step
     * that cannot start, is interrupted, or exits non-zero is a {@code BUILD}
     * launch failure naming the step and carrying the tool output.
     */
    private void runSetupStep(String language, String step, List<String> command)
            throws ServerLaunchException {
        runSetupStep(language, step, command, workDirectory);
    }

    private void runSetupStep(String language, String step, List<String> command, Path directory)
            throws ServerLaunchException {
        Instant startedAt = Instant.now();
        try {
            runSetupStepUntimed(language, step, command, directory);
        } finally {
            LaunchTimings.log(language, step, startedAt);
        }
    }

    private void runSetupStepUntimed(String language, String step, List<String> command,
            Path directory) throws ServerLaunchException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(directory.toFile());
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
        return "the " + language + " Language_Server environment step '" + step
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
