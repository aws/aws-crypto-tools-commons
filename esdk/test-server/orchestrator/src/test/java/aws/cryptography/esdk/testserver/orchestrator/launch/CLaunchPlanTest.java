package aws.cryptography.esdk.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link CLaunchPlan}: the pure command construction reproduces
 * the C server Makefile's {@code configure} + {@code build-server} recipes
 * (including the {@code CMAKE_PREFIX_PATH} pass-through) and the binary
 * launch, and a run whose materialized sources lack the server directory is a
 * {@code RESOLVE} launch failure naming the language — all without running a
 * real cmake build (the end-to-end launch is exercised by the orchestrated
 * run).
 */
class CLaunchPlanTest {

    private static final Path REPO = Path.of("/scratch/clones/aws-encryption-sdk-c");
    private static final Path SERVER = REPO.resolve("test-server");
    private static final Path BUILD = SERVER.resolve(CLaunchPlan.BUILD_DIR);

    // ------------------------------------------------------------------
    // Pure command construction (the Makefile configure/build-server recipes).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("configure targets the repo root with BUILD_TEST_SERVER=ON and the C++ KMS component off")
    void configure() {
        assertEquals(
            List.of("cmake", "-S", REPO.toString(), "-B", BUILD.toString(),
                "-DBUILD_TEST_SERVER=ON", "-DBUILD_AWS_ENC_SDK_CPP=OFF"),
            CLaunchPlan.configureCommand("cmake", REPO, BUILD, null));
    }

    @Test
    @DisplayName("a set CMAKE_PREFIX_PATH passes through to the configure, like the Makefile")
    void configureWithPrefixPath() {
        List<String> command =
            CLaunchPlan.configureCommand("cmake", REPO, BUILD, "/opt/awsdeps");
        assertEquals("-DCMAKE_PREFIX_PATH=/opt/awsdeps", command.get(command.size() - 1));
    }

    @Test
    @DisplayName("a blank CMAKE_PREFIX_PATH is not passed through")
    void configureWithBlankPrefixPath() {
        assertEquals(
            CLaunchPlan.configureCommand("cmake", REPO, BUILD, null),
            CLaunchPlan.configureCommand("cmake", REPO, BUILD, "  "));
    }

    @Test
    @DisplayName("the build targets only esdk-test-server, parallel, like build-server")
    void build() {
        assertEquals(
            List.of("cmake", "--build", BUILD.toString(),
                "--target", "esdk-test-server", "--", "-j"),
            CLaunchPlan.buildCommand("cmake", BUILD));
    }

    @Test
    @DisplayName("the server runs as <.build>/test-server/esdk-test-server <port>")
    void serverCommand() {
        assertEquals(
            List.of(BUILD.resolve("test-server/esdk-test-server").toString(), "8096"),
            CLaunchPlan.serverCommand(BUILD, 8096));
    }

    // ------------------------------------------------------------------
    // RESOLVE failure path (Requirement 2.5): missing materialized sources
    // abort before any cmake step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized c server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        CLaunchPlan plan = new CLaunchPlan(tempDir, "cmake",
            new SubprocessLauncher(Duration.ofSeconds(1)));
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(cEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("c", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("server:c"),
            "the abort must identify the missing component");
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static ConfigurationEntry cEntry() {
        return new ConfigurationEntry("c", 2, 8096, null, null, null, null);
    }
}
