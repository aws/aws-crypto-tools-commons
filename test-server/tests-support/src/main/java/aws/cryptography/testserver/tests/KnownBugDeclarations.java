package aws.cryptography.testserver.tests;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The runtime known-bug registry the {@code Tests} consult when gating an
 * assertion a catalogued bug breaks, resolved once per JVM from the
 * {@code testserver.knownBugs} runtime property the orchestrator injects —
 * mirroring {@link FeatureDeclarations}, and the injection-based counterpart to
 * the classpath {@link KnownBugs} ledger.
 *
 * <p>The orchestrator flattens each server's {@code bug-config.json}
 * exhibited-bug list (validated against the commons bug ledger) into
 * {@code testserver.knownBugs} = {@code <language>:<id>[;<id>…]} CSV, e.g.
 * {@code java:some-bug;another-bug,rust:some-bug} (read from the system property
 * first, then the {@code TESTSERVER_KNOWN_BUGS} environment variable).
 *
 * <p>Unlike Feature support, absence here is <em>not</em> a configuration error:
 * a bug a language does not declare is simply not exhibited, so
 * {@link #exhibits(String, String)} returns {@code false} for an unconfigured
 * registry, an undeclared language, or an undeclared id — the assertion then
 * runs with its full power to fail. This is the normal case (no bug), which is
 * why it is never treated as missing configuration.
 */
public final class KnownBugDeclarations {

    /** Runtime-config key: comma-separated {@code lang:id[;id…]} entries. */
    public static final String KNOWN_BUGS_PROPERTY = "testserver.knownBugs";
    public static final String KNOWN_BUGS_ENV = "TESTSERVER_KNOWN_BUGS";

    private static volatile KnownBugDeclarations instance;

    /** language -> the bug ids that language declares it exhibits. */
    private final Map<String, Set<String>> byLanguage;

    private KnownBugDeclarations(Map<String, Set<String>> byLanguage) {
        this.byLanguage = byLanguage;
    }

    /**
     * @return the process-wide registry, resolving {@value #KNOWN_BUGS_PROPERTY}
     *     on first access (once per JVM). An absent property yields an empty
     *     registry; a malformed one fails here.
     */
    public static KnownBugDeclarations shared() {
        KnownBugDeclarations local = instance;
        if (local == null) {
            synchronized (KnownBugDeclarations.class) {
                local = instance;
                if (local == null) {
                    local = parse(configuredValue());
                    instance = local;
                }
            }
        }
        return local;
    }

    /**
     * Parse the {@code lang:id[;id…]} CSV into a registry. {@code null} or blank
     * means "no known bug declared" — an empty registry. Public so per-SDK unit
     * tests can exercise parsing without the JVM-wide singleton or system
     * properties.
     */
    public static KnownBugDeclarations parse(String raw) {
        Map<String, Set<String>> byLanguage = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return new KnownBugDeclarations(byLanguage);
        }
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int colon = trimmed.indexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException(
                    "malformed known-bug entry (expected language:id[;id...]): " + trimmed);
            }
            String language = trimmed.substring(0, colon).trim();
            if (language.isEmpty()) {
                throw new IllegalArgumentException("blank language in known-bug entry: " + trimmed);
            }
            if (byLanguage.containsKey(language)) {
                throw new IllegalArgumentException(
                    "duplicate language in " + KNOWN_BUGS_PROPERTY + ": " + language);
            }
            Set<String> ids = new LinkedHashSet<>();
            for (String id : trimmed.substring(colon + 1).split(";")) {
                String name = id.trim();
                if (name.isEmpty()) {
                    continue;
                }
                if (!ids.add(name)) {
                    throw new IllegalArgumentException(
                        "duplicate bug id '" + name + "' declared for language '" + language + "'");
                }
            }
            if (ids.isEmpty()) {
                throw new IllegalArgumentException(
                    "language '" + language + "' declares no bug ids in " + KNOWN_BUGS_PROPERTY);
            }
            byLanguage.put(language, ids);
        }
        return new KnownBugDeclarations(byLanguage);
    }

    /**
     * @return whether {@code language} declares it exhibits the bug {@code id}.
     *     {@code false} when the registry is empty, the language is absent, or
     *     the id is not among the language's declared ids — a bug not declared
     *     is simply not exhibited.
     */
    public boolean exhibits(String language, String id) {
        Set<String> ids = byLanguage.get(language);
        return ids != null && ids.contains(id);
    }

    private static String configuredValue() {
        String fromProperty = System.getProperty(KNOWN_BUGS_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return System.getenv(KNOWN_BUGS_ENV);
    }
}
