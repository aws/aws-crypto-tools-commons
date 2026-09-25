package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.testserver.orchestrator.source.SourcePlan;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link PythonLaunchPlan}: the pure command construction
 * reproduces the Makefile's {@code setup-python} + {@code run-python-server}
 * flow against the resolved sources, and a run whose materialized sources lack
 * the Python library or server directory is a {@code RESOLVE} launch failure
 * naming the language — all without running a real venv/pip.
 */
class PythonLaunchPlanTest {

    private static final Path WORK = Path.of("/scratch/python-launch");
    private static final Path VENV = PythonLaunchPlan.venvDirectory(WORK);
    private static final Path LIBRARY = Path.of("/scratch/clones/aws-encryption-sdk-python");
    private static final Path SERVER = Path.of("/repo/esdk/test-server/servers/python");

    // ------------------------------------------------------------------
    // Pure command construction (the Makefile flow, resolved sources).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the venv is created with python3 -m venv in the plan's work directory")
    void venvCreation() {
        assertEquals(Path.of("/scratch/python-launch/venv"), VENV,
            "the venv lives inside the plan-owned work directory");
        assertEquals(
            List.of("python3", "-m", "venv", VENV.toString()),
            PythonLaunchPlan.createVenvCommand("python3", VENV));
    }

    @Test
    @DisplayName("pip is upgraded first, exactly as setup-python does")
    void pipUpgrade() {
        assertEquals(
            List.of(VENV.resolve("bin").resolve("pip").toString(),
                "install", "--quiet", "--upgrade", "pip"),
            PythonLaunchPlan.upgradePipCommand(VENV));
    }

    @Test
    @DisplayName("one editable install: -e <materialized library>, MPL, cbor2, -e <server> in setup-python order")
    void pipInstall() {
        List<String> command = PythonLaunchPlan.pipInstallCommand(VENV, LIBRARY, SERVER);
        assertEquals(
            List.of(VENV.resolve("bin").resolve("pip").toString(), "install", "--quiet",
                "-e", LIBRARY.toString(),
                PythonLaunchPlan.MPL_REQUIREMENT,
                PythonLaunchPlan.CBOR2_REQUIREMENT,
                "-e", SERVER.toString()),
            command);
        assertTrue(command.indexOf(LIBRARY.toString()) < command.indexOf(SERVER.toString()),
            "the resolved library installs before the server package, like setup-python");
        assertEquals("aws-cryptographic-material-providers>=1.7.4,<=1.11.2",
            PythonLaunchPlan.MPL_REQUIREMENT,
            "the MPL version range matches the Makefile pin");
    }

    @Test
    @DisplayName("the server runs as <venv python> -m esdk_test_server <port>, like run-python-server")
    void serverCommand() {
        assertEquals(
            List.of(VENV.resolve("bin").resolve("python").toString(),
                "-m", "esdk_test_server", "8092"),
            PythonLaunchPlan.serverCommand(VENV, 8092));
    }

    // ------------------------------------------------------------------
    // RESOLVE failure paths: missing materialized sources abort before any
    // venv/pip step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized python library is a RESOLVE failure naming the language")
    void missingLibraryIsResolveFailure(@TempDir Path tempDir) {
        PythonLaunchPlan plan = newPlan(tempDir);
        MaterializedSources sources = new MaterializedSources(List.of(serverSuccess()));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(pythonEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("python", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("library:python"),
            "the abort must identify the missing component");
    }

    @Test
    @DisplayName("a run with no materialized python server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        PythonLaunchPlan plan = newPlan(tempDir);
        MaterializedSources sources = new MaterializedSources(List.of(librarySuccess()));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(pythonEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("python", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("server:python"),
            "the abort must identify the missing component");
    }

    @Test
    @DisplayName("empty materialized sources fail on the library first (nothing is spawned)")
    void emptySourcesFailOnLibrary(@TempDir Path tempDir) {
        PythonLaunchPlan plan = newPlan(tempDir);
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(pythonEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertTrue(ex.getMessage().contains("library:python"));
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static PythonLaunchPlan newPlan(Path workDir) {
        // A short readiness window keeps any accidental launch fast; the
        // RESOLVE paths under test abort before the launcher is ever reached.
        return new PythonLaunchPlan(workDir, "python3",
            new SubprocessLauncher(Duration.ofSeconds(1)));
    }

    private static ConfigurationEntry pythonEntry() {
        return new ConfigurationEntry("python", 4, 8092, null, null, null, null);
    }

    private static MaterializedSources.Success librarySuccess() {
        return new MaterializedSources.Success(
            ComponentId.library("python"),
            new SourcePlan.Clone("https://github.com/aws/aws-encryption-sdk-python", "master", "."),
            ResolutionReason.CONFIGURATION_ENTRY,
            LIBRARY, "0123456789abcdef0123456789abcdef01234567", "master", null);
    }

    private static MaterializedSources.Success serverSuccess() {
        return new MaterializedSources.Success(
            ComponentId.server("python"),
            new SourcePlan.WorkingTree(Path.of("/repo"), "esdk/test-server/servers/python"),
            ResolutionReason.CONFIGURATION_ENTRY,
            SERVER, "89abcdef0123456789abcdef0123456789abcdef", "main", false);
    }
}
