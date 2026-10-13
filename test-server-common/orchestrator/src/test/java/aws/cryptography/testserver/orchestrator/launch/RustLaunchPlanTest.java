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
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit test for {@link RustLaunchPlan}'s language neutrality: the plan keys
 * every resolution and error off the entry's language, never a hardcoded
 * {@code "rust"} — the property the {@code rust-dafny} entry relies on to
 * reuse this plan for the Dafny-generated aws-esdk crate's server.
 */
class RustLaunchPlanTest {

    @Test
    @DisplayName("a rust-dafny entry resolves the server:rust-dafny component and names rust-dafny on failure")
    void rustDafnyEntryResolvesItsOwnComponent(@TempDir Path tempDir) {
        RustLaunchPlan plan = new RustLaunchPlan(tempDir, "esdk", "cargo",
            new SubprocessLauncher(Duration.ofSeconds(1)));
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(
                new ConfigurationEntry("rust-dafny", 1, 8098, null, null, null, null),
                sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("rust-dafny", ex.language(), "the abort must name the entry's language");
        assertTrue(ex.getMessage().contains("server:rust-dafny"),
            "the plan must resolve the entry's own server component");
    }

    private static final String RUST_SERVER = "esdk-test-servers/rust";

    @Test
    @DisplayName("a smithy-dafny runtimes/rust library generates and transpiles with polymorph_rust and transpile_rust")
    void rustTranspileCommands() {
        assertEquals(List.of("make", "polymorph_rust"), RustLaunchPlan.polymorphCommand("make"));
        assertEquals(List.of("make", "transpile_rust", "CORES=4"), RustLaunchPlan.transpileCommand("make"));
    }

    @Test
    @DisplayName("the code generator gets JAVA_HOME only when the codegen JDK is set")
    void codegenJavaHome() {
        assertEquals(Map.of(), RustLaunchPlan.codegenEnvironment(null));
        assertEquals(Map.of(), RustLaunchPlan.codegenEnvironment(" "));
        assertEquals(Map.of("JAVA_HOME", "/jdk17"), RustLaunchPlan.codegenEnvironment("/jdk17"));
    }

    @Test
    @DisplayName("a smithy-dafny library without dafny on PATH is a BUILD failure before any make or cargo step")
    void smithyDafnyLibraryRequiresDafny(@TempDir Path tempDir) throws Exception {
        assumeFalse(DafnyProject.commandOnPath("dafny", System.getenv("PATH")), "dafny is on PATH");
        String library = "AwsEncryptionSDK/runtimes/rust";
        DafnyLibraryFixture clone = DafnyLibraryFixture.create(tempDir, RUST_SERVER, library, true);
        RustLaunchPlan plan = new RustLaunchPlan(tempDir.resolve("work"), "esdk",
            clone.tool(tempDir, "cargo").toString(), clone.tool(tempDir, "make").toString(),
            new SubprocessLauncher(Duration.ofSeconds(1)));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class, () -> plan.launch(
            new ConfigurationEntry("rust-dafny", 1, 8098, null, null, null, null),
            clone.sources("rust-dafny", RUST_SERVER, library)));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertTrue(ex.getMessage().contains("requires Dafny " + RustLaunchPlan.REQUIRED_DAFNY_VERSION),
            ex.getMessage());
        assertEquals(List.of(), clone.toolCalls(), "nothing may run before the Dafny gate");
    }

    @Test
    @DisplayName("a hand-written library crate builds with cargo directly, without a transpile")
    void handWrittenLibraryIsNotTranspiled(@TempDir Path tempDir) throws Exception {
        DafnyLibraryFixture clone = DafnyLibraryFixture.create(tempDir, "esdk-test-server", "esdk", false);
        RustLaunchPlan plan = new RustLaunchPlan(tempDir.resolve("work"), "esdk",
            clone.tool(tempDir, "cargo").toString(), clone.tool(tempDir, "make").toString(),
            new SubprocessLauncher(Duration.ofSeconds(1)));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class, () -> plan.launch(
            new ConfigurationEntry("rust", 1, 8093, null, null, null, null),
            clone.sources("rust", "esdk-test-server", "esdk")));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertEquals(List.of("cargo build --release"), clone.toolCalls());
    }
}
