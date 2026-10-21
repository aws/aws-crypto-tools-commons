package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BuildStampTest {

    private static final String COMMIT = "0123456789abcdef0123456789abcdef01234567";

    @TempDir
    Path directory;

    @Test
    @DisplayName("a stamped commit with its outputs present is up to date")
    void upToDate() throws Exception {
        Path binary = Files.createFile(directory.resolve("server"));
        BuildStamp stamp = new BuildStamp(directory, "esdk");
        stamp.write("rust", COMMIT, null);

        assertTrue(stamp.upToDate(COMMIT, null, List.of(binary)));
        assertTrue(stamp.upToDate(COMMIT, false, List.of(binary)));
    }

    @Test
    @DisplayName("another commit, a missing output, or a dirty tree forces the build")
    void notUpToDate() throws Exception {
        Path binary = Files.createFile(directory.resolve("server"));
        BuildStamp stamp = new BuildStamp(directory, "esdk");
        stamp.write("rust", COMMIT, null);

        assertFalse(stamp.upToDate("f".repeat(40), null, List.of(binary)));
        assertFalse(stamp.upToDate(COMMIT, null, List.of(directory.resolve("absent"))));
        assertFalse(stamp.upToDate(COMMIT, true, List.of(binary)));
        assertFalse(stamp.upToDate(null, null, List.of(binary)));
    }

    @Test
    @DisplayName("a build from a dirty tree clears the stamp, so the clean commit rebuilds")
    void dirtyBuildClearsStamp() throws Exception {
        Path binary = Files.createFile(directory.resolve("server"));
        BuildStamp stamp = new BuildStamp(directory, "esdk");
        stamp.write("rust", COMMIT, null);
        stamp.write("rust", COMMIT, true);

        assertFalse(stamp.upToDate(COMMIT, false, List.of(binary)));
    }
}
