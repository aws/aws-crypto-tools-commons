package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link NodeLaunchPlan}: the pure command construction
 * reproduces the JavaScript server Makefile's {@code build-server} flow (root
 * {@code npm ci} + {@code npm run build-node}, then {@code tsc} in the server
 * directory) and the {@code node <entry> <port>} launch, and a run whose
 * materialized sources lack the server directory is a {@code RESOLVE} launch
 * failure naming the language — all without running a real npm build (the
 * end-to-end launch is exercised by the orchestrated run).
 */
class NodeLaunchPlanTest {

    private static final Path SERVER =
        Path.of("/scratch/clones/aws-encryption-sdk-javascript/test-server");

    // ------------------------------------------------------------------
    // Pure command construction (the Makefile build-server flow).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("repository dependencies install with npm ci --unsafe-perm, like build-server")
    void install() {
        assertEquals(List.of("npm", "ci", "--unsafe-perm"),
            NodeLaunchPlan.installCommand("npm"));
    }

    @Test
    @DisplayName("the workspace modules build with npm run build-node, like build-server")
    void buildModules() {
        assertEquals(List.of("npm", "run", "build-node"),
            NodeLaunchPlan.buildModulesCommand("npm"));
    }

    @Test
    @DisplayName("the server compiles with npx tsc -p tsconfig.json in the server directory")
    void buildServer() {
        assertEquals(List.of("npx", "tsc", "-p", "tsconfig.json"),
            NodeLaunchPlan.buildServerCommand());
    }

    @Test
    @DisplayName("the server runs as node <server>/build/src/main.js <port>")
    void serverCommand() {
        assertEquals(
            List.of("node", SERVER.resolve("build/src/main.js").toString(), "8095"),
            NodeLaunchPlan.serverCommand("node", SERVER, 8095));
    }

    // ------------------------------------------------------------------
    // RESOLVE failure path (Requirement 2.5): missing materialized sources
    // abort before any npm step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized javascript server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        NodeLaunchPlan plan = new NodeLaunchPlan(tempDir, "esdk", "npm", "node",
            new SubprocessLauncher(Duration.ofSeconds(1)));
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(javascriptEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("javascript", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("server:javascript"),
            "the abort must identify the missing component");
    }

    // ------------------------------------------------------------------
    // Build stamp guard: pure over a constructed server directory.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the build is up to date only when the stamp holds the exact commit, the entry point exists, and the source is clean")
    void buildUpToDate(@TempDir Path serverDir) throws Exception {
        String commit = "0123456789abcdef0123456789abcdef01234567";

        assertFalse(NodeLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp"),
            "no stamp, no entry point: build required");

        Files.createDirectories(serverDir.resolve("build/src"));
        Files.writeString(serverDir.resolve(NodeLaunchPlan.SERVER_ENTRY), "// entry");
        assertFalse(NodeLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp"),
            "entry point without a stamp: build required");

        Files.writeString(serverDir.resolve(".esdk-build-stamp"), commit + "\n");
        assertTrue(NodeLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp"),
            "matching stamp + entry point (clone): build skipped");

        assertTrue(NodeLaunchPlan.buildUpToDate(serverDir, commit, Boolean.FALSE, ".esdk-build-stamp"),
            "matching stamp + entry point + clean working tree: build skipped");

        assertFalse(NodeLaunchPlan.buildUpToDate(serverDir, commit, Boolean.TRUE, ".esdk-build-stamp"),
            "matching stamp but dirty working tree: build required (uncommitted source may not match the stamped commit)");

        assertFalse(NodeLaunchPlan.buildUpToDate(serverDir, "f".repeat(40), null, ".esdk-build-stamp"),
            "a different commit never reuses the stamped build");

        Files.delete(serverDir.resolve(NodeLaunchPlan.SERVER_ENTRY));
        assertFalse(NodeLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp"),
            "matching stamp without the entry point: build required");
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static ConfigurationEntry javascriptEntry() {
        return new ConfigurationEntry("javascript", 5, 8095, null, null, null, null);
    }
}
