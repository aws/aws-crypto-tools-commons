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
 * Unit test for {@link RustLaunchPlan}'s language neutrality: the plan keys
 * every resolution and error off the entry's language, never a hardcoded
 * {@code "rust"} — the property the {@code rust-dafny} entry relies on to
 * reuse this plan for the Dafny-generated aws-esdk crate's server.
 */
class RustLaunchPlanTest {

    @Test
    @DisplayName("a rust-dafny entry resolves the server:rust-dafny component and names rust-dafny on failure")
    void rustDafnyEntryResolvesItsOwnComponent(@TempDir Path tempDir) {
        RustLaunchPlan plan = new RustLaunchPlan(tempDir, "cargo",
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
}
