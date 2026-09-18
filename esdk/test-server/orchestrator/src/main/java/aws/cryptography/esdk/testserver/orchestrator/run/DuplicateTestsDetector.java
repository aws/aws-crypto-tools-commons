package aws.cryptography.esdk.testserver.orchestrator.run;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Detects how many {@code Tests} definitions exist under the ESDK TestServer
 * directory (Requirement 7.1, 7.5). The single canonical {@code Tests} suite is
 * identified by its Gradle root name {@code esdk-test-server-tests} declared in a
 * {@code settings.gradle.kts}; more than one such definition means duplicate
 * {@code Tests}, which must abort the run before any Test executes (Requirement
 * 7.5).
 *
 * <p>Kept filesystem-based and injectable (any base directory) so the
 * duplicate-detection error path can be exercised by an integration test against
 * a temporary directory without touching the real tree.
 */
public final class DuplicateTestsDetector {

    /** The Gradle root-project name that marks the single canonical Tests suite. */
    public static final String TESTS_ROOT_NAME = "esdk-test-server-tests";

    private static final String SETTINGS_FILE = "settings.gradle.kts";

    /**
     * @return the directories under {@code baseDir} that define a {@code Tests}
     *     suite (i.e. contain a {@code settings.gradle.kts} naming the root
     *     project {@link #TESTS_ROOT_NAME}). Never null.
     */
    public List<Path> findTestsDefinitions(Path baseDir) {
        if (!Files.isDirectory(baseDir)) {
            return List.of();
        }
        List<Path> found = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(baseDir)) {
            walk.filter(p -> p.getFileName() != null
                    && SETTINGS_FILE.equals(p.getFileName().toString()))
                .forEach(settings -> {
                    if (namesTestsRoot(settings)) {
                        found.add(settings.getParent());
                    }
                });
        } catch (IOException e) {
            throw new UncheckedIOException("could not scan for Tests definitions under " + baseDir, e);
        }
        return found;
    }

    private static boolean namesTestsRoot(Path settings) {
        try {
            String content = Files.readString(settings);
            // Match: rootProject.name = "esdk-test-server-tests"
            return content.contains("rootProject.name")
                && content.contains("\"" + TESTS_ROOT_NAME + "\"");
        } catch (IOException e) {
            return false;
        }
    }
}
