package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Line coverage for a Language_Server's library, on when
 * {@value #DIRECTORY_VARIABLE} names a directory.
 *
 * <p>A launch plan that supports coverage calls {@link #start} and runs its
 * server so the server writes its raw coverage data under the returned
 * directory, {@code <coverage dir>/<language>/}. {@link #start} also writes
 * {@code meta.json} there: the language, the coverage tool, the library's
 * repository and commit, and the repository's root on this machine.
 * {@code test-server-common/tools/coverage_report.py} reads it after the run
 * and turns the raw data into {@code <language>.lcov} with paths relative to
 * that root.
 */
public final class Coverage {
    /** The environment variable that turns coverage on and names its directory. */
    public static final String DIRECTORY_VARIABLE = "TESTSERVER_COVERAGE_DIR";

    private static final ObjectMapper JSON = new ObjectMapper();

    private Coverage() {
    }

    /** The coverage directory from the environment, when coverage is on. */
    static Optional<Path> root() {
        String value = System.getenv(DIRECTORY_VARIABLE);
        return value == null || value.isBlank() ? Optional.empty() : Optional.of(Path.of(value).toAbsolutePath());
    }

    /**
     * Prepares {@code <coverage dir>/<language>/} and its {@code meta.json},
     * when coverage is on.
     *
     * @param tool   the converter coverage_report.py runs, for example {@code llvm}
     * @param extras tool-specific fields, for example the instrumented binaries
     * @return the directory the server writes its raw data to, or empty when coverage is off
     */
    static Optional<Path> start(ConfigurationEntry entry, MaterializedSources sources, String tool,
            Map<String, Object> extras) throws ServerLaunchException {
        Optional<Path> root = root();
        if (root.isEmpty()) {
            return Optional.empty();
        }
        String language = entry.language();
        Optional<MaterializedSources.Success> library = sources.successOf(ComponentId.library(language))
            .or(() -> sources.successOf(ComponentId.server(language)));
        if (library.isEmpty()) {
            return Optional.empty();
        }
        Path directory = root.get().resolve(language);
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("language", language);
        meta.put("tool", tool);
        meta.put("repository", repositorySlug(entry.libraryRepository().url()));
        meta.put("commit", library.get().commit());
        meta.put("root", library.get().root().toAbsolutePath().normalize().toString());
        meta.put("library", library.get().directory().toAbsolutePath().normalize().toString());
        meta.putAll(extras);
        try {
            Files.createDirectories(directory);
            JSON.writerWithDefaultPrettyPrinter().writeValue(directory.resolve("meta.json").toFile(), meta);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to prepare the " + language + " coverage directory " + directory + ": "
                    + e.getMessage(), e);
        }
        System.out.println("[coverage] " + language + ": " + tool + " data under " + directory);
        return Optional.of(directory);
    }

    /** {@code owner/repo} from a GitHub HTTPS or SSH URL. */
    static String repositorySlug(String url) {
        String slug = url.replaceFirst("^.*github\\.com[:/]", "").replaceFirst("\\.git$", "");
        return slug.replaceFirst("/+$", "");
    }
}
