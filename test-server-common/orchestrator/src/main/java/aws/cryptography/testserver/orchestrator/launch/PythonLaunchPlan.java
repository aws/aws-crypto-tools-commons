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
 *       package. Any failing step is a {@code BUILD} launch failure naming the
 *       step and carrying the tool output.</li>
 *   <li><b>Launch.</b> {@code <venv python> -m
 *       esdk_test_server <port>} from the server directory, via the shared
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

    /** The server's Python module: {@code python -m esdk_test_server <port>}. */
    static final String SERVER_MODULE = "esdk_test_server";

    /** The interpreter used to create the venv (the Makefile's {@code PYTHON3 ?= python3}). */
    static final String DEFAULT_PYTHON3 = "python3";

    private static final String VENV_DIR_NAME = "venv";
    private static final String SERVER_LOG_NAME = "python-server.log";

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final String python3;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      venv and the server log
     */
    public PythonLaunchPlan(Path workDirectory) {
        this(workDirectory, DEFAULT_PYTHON3, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param python3            the interpreter used to create the venv
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public PythonLaunchPlan(Path workDirectory, String python3, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (python3 == null || python3.isBlank()) {
            throw new IllegalArgumentException("python3 is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.python3 = python3;
        this.subprocessLauncher = subprocessLauncher;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized library + server directories.
        Path libraryDir = sources.directoryOf(ComponentId.library(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.library(language)));
        Path serverDir = sources.directoryOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));

        // 2. Environment: venv + editable installs (the Makefile's setup-python).
        Path venvDir = venvDirectory(workDirectory);
        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }
        if (!Files.isExecutable(venvPython(venvDir))) {
            runSetupStep(language, "create venv", createVenvCommand(python3, venvDir));
        }
        runSetupStep(language, "upgrade pip", upgradePipCommand(venvDir));
        runSetupStep(language, "pip install library + MPL + cbor2 + server",
            pipInstallCommand(venvDir, libraryDir, serverDir));

        // 3. Launch: <venv python> -m esdk_test_server <port> from the server
        //    directory (the Makefile's run-python-server), via the shared
        //    probe/spawn/readiness/teardown machinery.
        ProcessBuilder server = new ProcessBuilder(serverCommand(venvDir, entry.port()));
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

    /** {@code <venv python> -m esdk_test_server <port>}. */
    static List<String> serverCommand(Path venvDir, int port) {
        return List.of(venvPython(venvDir).toString(), "-m", SERVER_MODULE, String.valueOf(port));
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
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(workDirectory.toFile());
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
