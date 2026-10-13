package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
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
    @DisplayName("the server builds with go build -buildvcs=false -o esdk-test-server .")
    void build() {
        assertEquals(List.of("go", "build", "-buildvcs=false", "-o", "esdk-test-server", "."),
            GoLaunchPlan.buildCommand("go", "esdk-test-server"));
    }

    @Test
    @DisplayName("the server runs as <server>/esdk-test-server <port>")
    void serverCommand() {
        assertEquals(
            List.of(SERVER.resolve("esdk-test-server").toString(), "8099"),
            GoLaunchPlan.serverCommand(SERVER, 8099, "esdk-test-server"));
    }

    // ------------------------------------------------------------------
    // RESOLVE failure path (Requirement 2.5): missing materialized sources
    // abort before any go step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized go server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        GoLaunchPlan plan = new GoLaunchPlan(tempDir, "esdk", "go",
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

    @Test
    @DisplayName("a smithy-dafny runtimes/go library transpiles its implementation and MPL dependencies, not its tests")
    void goTranspileCommand() {
        assertEquals(List.of("make", "_no_extern_pre_transpile", "transpile_dependencies_go",
                "transpile_implementation_go", "_no_extern_post_transpile", "CORES=4"),
            GoLaunchPlan.transpileCommand("make"));
    }

    @Test
    @DisplayName("a smithy-dafny library without dafny on PATH is a BUILD failure before any make or go step")
    void smithyDafnyLibraryRequiresDafny(@TempDir Path tempDir) throws Exception {
        assumeFalse(DafnyProject.commandOnPath("dafny", System.getenv("PATH")), "dafny is on PATH");
        String server = "esdk-test-servers/go";
        String library = "AwsEncryptionSDK/runtimes/go";
        DafnyLibraryFixture clone = DafnyLibraryFixture.create(tempDir, server, library, true);
        GoLaunchPlan plan = new GoLaunchPlan(tempDir.resolve("work"), "esdk",
            clone.tool(tempDir, "go").toString(), clone.tool(tempDir, "make").toString(),
            new SubprocessLauncher(Duration.ofSeconds(1)));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(goEntry(), clone.sources("go", server, library)));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertTrue(ex.getMessage().contains("requires Dafny " + GoLaunchPlan.REQUIRED_DAFNY_VERSION),
            ex.getMessage());
        assertEquals(List.of(), clone.toolCalls(), "nothing may run before the Dafny gate");
    }

    @Test
    @DisplayName("a library that is not a smithy-dafny runtimes/go builds with go directly, without a transpile")
    void plainLibraryIsNotTranspiled(@TempDir Path tempDir) throws Exception {
        String server = "esdk-test-servers/go";
        String library = "releases/go/encryption-sdk";
        DafnyLibraryFixture clone = DafnyLibraryFixture.create(tempDir, server, library, false);
        GoLaunchPlan plan = new GoLaunchPlan(tempDir.resolve("work"), "esdk",
            clone.tool(tempDir, "go").toString(), clone.tool(tempDir, "make").toString(),
            new SubprocessLauncher(Duration.ofSeconds(1)));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(goEntry(), clone.sources("go", server, library)));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertEquals(List.of("go build -buildvcs=false -o esdk-test-server ."), clone.toolCalls());
    }
}
