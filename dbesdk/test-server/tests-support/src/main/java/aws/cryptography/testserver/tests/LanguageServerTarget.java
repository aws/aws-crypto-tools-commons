package aws.cryptography.testserver.tests;

import java.net.URI;
import java.util.Objects;

/**
 * A single Language_Server target the {@code Tests} can drive, identified by the
 * tuple of <strong>language</strong> and <strong>major version</strong> plus the
 * base endpoint URL it is reachable at.
 *
 * <p>Server targets are language-major-version entries, not bare languages: the
 * same language may ship multiple concurrently-supported major versions, and a
 * cross-language (really cross-(language,version)) round trip must be able to
 * name each one distinctly (for example {@code java-v3} vs a future
 * {@code java-v4}). For now only the latest major version of each language is
 * configured, but the identity is always the full tuple so adding another major
 * version later is purely additional configuration.
 *
 * <p>The endpoint is supplied by runtime configuration: the
 * orchestrator launches each Language_Server on its configured port and hands the
 * Tests the resulting {@code (language, majorVersion, repo, endpoint)} set via
 * {@code testserver.targets}. {@code repo} is the source repository name
 * (the {@code libraryRepository.name} from {@code server-config.json}), carried
 * so the identity fully distinguishes bug (code) sources — the same
 * {@code (language, majorVersion)} could be built from different repositories.
 * There is no in-process fallback — the Tests are endpoint-only.
 */
public record LanguageServerTarget(String language, int majorVersion, String repo, URI endpoint) {

    public LanguageServerTarget {
        Objects.requireNonNull(language, "language");
        Objects.requireNonNull(repo, "repo");
        Objects.requireNonNull(endpoint, "endpoint");
        if (language.isBlank()) {
            throw new IllegalArgumentException("language must be non-blank");
        }
        if (repo.isBlank()) {
            throw new IllegalArgumentException("repo must be non-blank");
        }
        if (majorVersion < 1) {
            throw new IllegalArgumentException("majorVersion must be >= 1, was " + majorVersion);
        }
    }

    /**
     * @return the stable, human-readable label for this target — {@code
     *     <language>-v<majorVersion>} (e.g. {@code java-v3}, {@code python-v4}) —
     *     used in test-execution names so each cross-language pair is legible in
     *     the report.
     */
    public String label() {
        return language + "-v" + majorVersion;
    }

    @Override
    public String toString() {
        return label();
    }
}
