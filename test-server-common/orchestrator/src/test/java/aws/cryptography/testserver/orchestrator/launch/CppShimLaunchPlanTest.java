package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.testserver.orchestrator.source.SourcePlan;
import java.io.File;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CppShimLaunchPlanTest {

    private static final String COMMIT = "0123456789abcdef0123456789abcdef01234567";

    @Test
    @DisplayName("the launched server finds the shim library through the loader search path, not the build-time rpath")
    void launchPutsShimLibraryDirectoryOnLoaderPath(@TempDir Path tempDir) throws Exception {
        assumeTrue(new File("/bin/sh").canExecute(), "needs /bin/sh for the stub server");

        // A materialized clone laid out as aws-crypto-tools-rust: the server crate
        // and the shim crate side by side, both already built (stamp current) so
        // the plan launches without running cargo.
        Path clone = tempDir.resolve("clone");
        Path serverDir = Files.createDirectories(clone.resolve("esdk-cpp-test-server"));
        Path shimRelease = Files.createDirectories(
            clone.resolve("esdk/shims/aws-esdk-cpp/target/release"));
        Files.writeString(shimRelease.resolve(System.mapLibraryName("aws_esdk_cpp")), "");
        Path binary = Files.createDirectories(serverDir.resolve("target/release"))
            .resolve("esdk-cpp-test-server");
        // The stub records the search path it was started with, then exits before
        // accepting a connection.
        String variable = CppShimLaunchPlan.libraryPathVariable(System.getProperty("os.name"));
        Files.writeString(binary, "#!/bin/sh\necho \"$" + variable + "\"\n", StandardCharsets.UTF_8);
        assertTrue(binary.toFile().setExecutable(true));
        new BuildStamp(serverDir, "esdk").write("rust-cpp", COMMIT, null);

        Path work = tempDir.resolve("work");
        CppShimLaunchPlan plan = new CppShimLaunchPlan(work, "esdk", "cargo",
            new SubprocessLauncher(Duration.ofSeconds(2)));
        MaterializedSources sources = new MaterializedSources(List.of(new MaterializedSources.Success(
            ComponentId.server("rust-cpp"),
            new SourcePlan.Clone("git@github.com:aws/aws-crypto-tools-rust.git", "main", "esdk-cpp-test-server"),
            ResolutionReason.CONFIGURATION_ENTRY, serverDir, COMMIT, "main", null)));

        assertThrows(ServerLaunchException.class, () -> plan.launch(
            new ConfigurationEntry("rust-cpp", 1, freePort(), null, null, null, null), sources));

        String seen = Files.readString(work.resolve("cpp-shim-server.log"), StandardCharsets.UTF_8).strip();
        assertEquals(shimRelease.toString(), seen.split(File.pathSeparator)[0],
            "the shim's target/release must lead the " + variable + " the server starts with");
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Test
    @DisplayName("macOS uses DYLD_LIBRARY_PATH; other platforms use LD_LIBRARY_PATH")
    void libraryPathVariablePerPlatform() {
        assertEquals("DYLD_LIBRARY_PATH", CppShimLaunchPlan.libraryPathVariable("Mac OS X"));
        assertEquals("LD_LIBRARY_PATH", CppShimLaunchPlan.libraryPathVariable("Linux"));
    }

    @Test
    @DisplayName("an existing search path is kept after the shim directory")
    void prependPathKeepsExistingEntries() {
        Path dir = Path.of("/shim/target/release");
        assertEquals(dir.toString(), CppShimLaunchPlan.prependPath(dir, null));
        assertEquals(dir + File.pathSeparator + "/usr/local/lib",
            CppShimLaunchPlan.prependPath(dir, "/usr/local/lib"));
    }
}
