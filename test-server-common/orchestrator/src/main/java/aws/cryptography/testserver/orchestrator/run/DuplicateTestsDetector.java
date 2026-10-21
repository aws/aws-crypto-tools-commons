package aws.cryptography.testserver.orchestrator.run;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Detects how many {@code Tests} definitions exist under the SDK's TestServer
 * directory (Requirement 7.1, 7.5). The single canonical {@code Tests} suite is
 * identified by its Gradle root name (e.g. {@code esdk-test-server-tests} or
 * {@code dbesdk-test-server-tests}) declared in a {@code settings.gradle.kts};
 * more than one such definition means duplicate {@code Tests}, which must
 * abort the run before any Test executes (Requirement 7.5).
 *
 * <p>Kept filesystem-based and injectable (any base directory, any expected
 * root-project name) so the duplicate-detection error path can be exercised by
 * an integration test against a temporary directory without touching the real
 * tree.
 */
public final class DuplicateTestsDetector {

    private static final String SETTINGS_FILE = "settings.gradle.kts";

    /**
     * @return the Gradle root-project name that marks the canonical Tests
     *     suite for {@code product}: {@code <product>-test-server-tests}
     *     (e.g. {@code esdk-test-server-tests} for {@code product == "esdk"}).
     *     Each SDK's tests module's {@code settings.gradle.kts} declares this
     *     exact name.
     */
    public static String testsRootNameForProduct(String product) {
        return product + "-test-server-tests";
    }

    /**
     * @return the directories under {@code baseDir} that define a {@code Tests}
     *     suite for the given {@code product}: a {@code settings.gradle.kts}
     *     naming the root project {@link #testsRootNameForProduct(String)}.
     *     Never null.
     */
    public List<Path> findTestsDefinitions(Path baseDir, String product) {
        return findTestsDefinitionsMatching(baseDir, testsRootNameForProduct(product));
    }

    /**
     * @return the directories under {@code baseDir} that define a {@code Tests}
     *     suite whose {@code settings.gradle.kts} names the root project
     *     exactly {@code testsRootName}. Never null. Package-private test seam
     *     used to exercise the scan without deriving a name from a product.
     */
    List<Path> findTestsDefinitionsMatching(Path baseDir, String testsRootName) {
        if (!Files.isDirectory(baseDir)) {
            return List.of();
        }
        List<Path> found = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(baseDir)) {
            walk.filter(p -> p.getFileName() != null
                    && SETTINGS_FILE.equals(p.getFileName().toString()))
                .forEach(settings -> {
                    if (namesRootProject(settings, testsRootName)) {
                        found.add(settings.getParent());
                    }
                });
        } catch (IOException e) {
            throw new UncheckedIOException("could not scan for Tests definitions under " + baseDir, e);
        }
        return found;
    }

    private static boolean namesRootProject(Path settings, String testsRootName) {
        try {
            String content = Files.readString(settings);
            // Match: rootProject.name = "<testsRootName>"
            return content.contains("rootProject.name")
                && content.contains("\"" + testsRootName + "\"");
        } catch (IOException e) {
            return false;
        }
    }
}
