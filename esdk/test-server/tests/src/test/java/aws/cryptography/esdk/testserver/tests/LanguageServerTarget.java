package aws.cryptography.esdk.testserver.tests;

import java.net.URI;
import java.util.Objects;

/**
 * A single Language_Server target the {@code Tests} can drive, identified by the
 * tuple of <strong>language</strong>, <strong>major version</strong>, and the
 * <strong>repository</strong> its library is built from, plus the base endpoint
 * URL it is reachable at.
 *
 * <p>Server targets are language-major-version-repository entries, not bare
 * languages: the same language may ship multiple concurrently-supported major
 * versions or be served from more than one repository, and a cross-language
 * (really cross-(language,version,repository)) round trip must be able to name
 * each one distinctly (for example {@code java-v3} vs a future {@code java-v4},
 * or a native vs a Dafny-sourced server of the same language). The repository is
 * also the identity a {@link KnownBugs} entry is declared against.
 *
 * <p>The endpoint is supplied by runtime configuration (Requirement 7.3): the
 * orchestrator launches each Language_Server on its configured port and hands the
 * Tests the resulting {@code (language, majorVersion, repository, endpoint)} set
 * via {@code esdk.testserver.targets}. There is no in-process fallback — the
 * Tests are endpoint-only (Requirement 10.2).
 */
public record LanguageServerTarget(String language, int majorVersion, String repository, URI endpoint) {

    public LanguageServerTarget {
        Objects.requireNonNull(language, "language");
        Objects.requireNonNull(repository, "repository");
        Objects.requireNonNull(endpoint, "endpoint");
        if (language.isBlank()) {
            throw new IllegalArgumentException("language must be non-blank");
        }
        if (repository.isBlank()) {
            throw new IllegalArgumentException("repository must be non-blank");
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
