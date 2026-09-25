package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link DotnetLaunchPlan}: the pure command construction
 * reproduces the .NET library's own transpile pipeline (submodule init +
 * {@code setup_net} + {@code transpile_net}) and the server Makefile's
 * {@code build-server}/run recipes, the {@code dafny}-on-PATH gate is pure over
 * a constructed PATH, and a run whose materialized sources lack the server
 * directory is a {@code RESOLVE} launch failure naming the language — all
 * without running a real Dafny transpile (the end-to-end launch is exercised
 * by the orchestrated run).
 */
class DotnetLaunchPlanTest {

    private static final Path SERVER =
        Path.of("/scratch/clones/aws-encryption-sdk/esdk-test-servers/net");

    // ------------------------------------------------------------------
    // Pure command construction (the repo's net pipeline + the Makefile).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the transpile prerequisites init the libraries and mpl submodules, like the repo's net workflow")
    void submodules() {
        assertEquals(List.of("git", "submodule", "update", "--init", "libraries"),
            DotnetLaunchPlan.submoduleLibrariesCommand());
        assertEquals(List.of("git", "submodule", "update", "--init", "--recursive", "mpl"),
            DotnetLaunchPlan.submoduleMplCommand());
    }

    @Test
    @DisplayName("the library restores with make setup_net and transpiles with make transpile_net CORES=4")
    void setupAndTranspile() {
        assertEquals(List.of("make", "setup_net"),
            DotnetLaunchPlan.setupCommand("make"));
        assertEquals(List.of("make", "transpile_net", "CORES=4"),
            DotnetLaunchPlan.transpileCommand("make"));
    }

    @Test
    @DisplayName("the server builds with dotnet build EsdkTestServer.csproj -c Release, like build-server")
    void build() {
        assertEquals(
            List.of("dotnet", "build", "EsdkTestServer.csproj", "-c", "Release"),
            DotnetLaunchPlan.buildCommand("dotnet", "EsdkTestServer.csproj"));
    }

    @Test
    @DisplayName("the server runs as dotnet <server>/bin/Release/net8.0/EsdkTestServer.dll <port>")
    void serverCommand() {
        assertEquals(
            List.of("dotnet",
                SERVER.resolve("bin/Release/net8.0/EsdkTestServer.dll").toString(), "8097"),
            DotnetLaunchPlan.serverCommand("dotnet", SERVER, 8097, "bin/Release/net8.0/EsdkTestServer.dll"));
    }

    // ------------------------------------------------------------------
    // The dafny-on-PATH gate (pure over a constructed PATH).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("an executable dafny on a PATH entry is found")
    void dafnyOnPath(@TempDir Path tempDir) throws IOException {
        Path dafny = tempDir.resolve("dafny");
        Files.writeString(dafny, "");
        Files.setPosixFilePermissions(dafny, Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE));
        String path = "/nonexistent" + File.pathSeparator + tempDir;

        assertTrue(DotnetLaunchPlan.commandOnPath("dafny", path));
    }

    @Test
    @DisplayName("a missing or empty PATH yields dafny-not-found")
    void dafnyAbsent(@TempDir Path tempDir) {
        assertFalse(DotnetLaunchPlan.commandOnPath("dafny", null));
        assertFalse(DotnetLaunchPlan.commandOnPath("dafny", ""));
        assertFalse(DotnetLaunchPlan.commandOnPath("dafny", tempDir.toString()),
            "a PATH entry without a dafny executable must not match");
    }

    // ------------------------------------------------------------------
    // RESOLVE failure path (Requirement 2.5): missing materialized sources
    // abort before the dafny gate or any make step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized net server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        DotnetLaunchPlan plan = new DotnetLaunchPlan(tempDir, "esdk", "dotnet", "make",
            new SubprocessLauncher(Duration.ofSeconds(1)));
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(netEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("net", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("server:net"),
            "the abort must identify the missing component");
    }

    // ------------------------------------------------------------------
    // Build stamp guard: pure over a constructed server directory.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the build is up to date only when the stamp holds the exact commit, the assembly exists, and the source is clean")
    void buildUpToDate(@TempDir Path serverDir) throws Exception {
        String commit = "0123456789abcdef0123456789abcdef01234567";
        String dllPath = "bin/Release/net8.0/EsdkTestServer.dll";

        assertFalse(DotnetLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp", dllPath),
            "no stamp, no assembly: build required");

        Path dll = serverDir.resolve(dllPath);
        Files.createDirectories(dll.getParent());
        Files.writeString(dll, "assembly");
        assertFalse(DotnetLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp", dllPath),
            "assembly without a stamp: build required");

        Files.writeString(serverDir.resolve(".esdk-build-stamp"), commit + "\n");
        assertTrue(DotnetLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp", dllPath),
            "matching stamp + assembly (clone): build skipped");

        assertTrue(DotnetLaunchPlan.buildUpToDate(serverDir, commit, Boolean.FALSE, ".esdk-build-stamp", dllPath),
            "matching stamp + assembly + clean working tree: build skipped");

        assertFalse(DotnetLaunchPlan.buildUpToDate(serverDir, commit, Boolean.TRUE, ".esdk-build-stamp", dllPath),
            "matching stamp but dirty working tree: build required (uncommitted source may not match the stamped commit)");

        assertFalse(DotnetLaunchPlan.buildUpToDate(serverDir, "f".repeat(40), null, ".esdk-build-stamp", dllPath),
            "a different commit never reuses the stamped build");

        Files.delete(dll);
        assertFalse(DotnetLaunchPlan.buildUpToDate(serverDir, commit, null, ".esdk-build-stamp", dllPath),
            "matching stamp without the assembly: build required");
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static ConfigurationEntry netEntry() {
        return new ConfigurationEntry("net", 5, 8097, null, null, null, null);
    }
}
