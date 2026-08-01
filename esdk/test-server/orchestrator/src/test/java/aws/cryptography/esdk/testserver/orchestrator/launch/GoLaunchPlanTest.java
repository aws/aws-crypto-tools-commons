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
 * Unit tests for {@link GoLaunchPlan}: the pure command construction
 * reproduces the Go server Makefile's {@code build-server} recipe and the
 * binary launch, and a run whose materialized sources lack the server
 * directory is a {@code RESOLVE} launch failure naming the language — all
 * without running a real go build (the end-to-end launch is exercised by the
 * orchestrated run).
 */
class GoLaunchPlanTest {

    private static final Path SERVER =
        Path.of("/scratch/clones/aws-encryption-sdk/esdk-test-servers/go");

    // ------------------------------------------------------------------
    // Pure command construction (the Makefile build-server recipe).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the server builds with go build -o esdk-test-server ., like build-server")
    void build() {
        assertEquals(List.of("go", "build", "-o", "esdk-test-server", "."),
            GoLaunchPlan.buildCommand("go"));
    }

    @Test
    @DisplayName("the server runs as <server>/esdk-test-server <port>")
    void serverCommand() {
        assertEquals(
            List.of(SERVER.resolve("esdk-test-server").toString(), "8099"),
            GoLaunchPlan.serverCommand(SERVER, 8099));
    }

    // ------------------------------------------------------------------
    // RESOLVE failure path (Requirement 2.5): missing materialized sources
    // abort before any go step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized go server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        GoLaunchPlan plan = new GoLaunchPlan(tempDir, "go",
            new SubprocessLauncher(Duration.ofSeconds(1)));
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(goEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("go", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("server:go"),
            "the abort must identify the missing component");
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static ConfigurationEntry goEntry() {
        return new ConfigurationEntry("go", 1, 8099, null, null, null, null);
    }
}
