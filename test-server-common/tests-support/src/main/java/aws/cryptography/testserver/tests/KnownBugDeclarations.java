package aws.cryptography.testserver.tests;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The runtime known-bug registry the {@code Tests} consult when gating an
 * assertion a catalogued bug breaks, resolved once per JVM from the
 * {@code testserver.knownBugs} runtime property the orchestrator injects —
 * mirroring {@link FeatureDeclarations}.
 *
 * <p>The orchestrator flattens each server's {@code bug-config.json}
 * exhibited-bug list (validated against the commons bug ledger), keyed by the
 * full source identity {@code (language, majorVersion, repo)} so bugs from
 * distinct code sources are never conflated — the same {@code language} and
 * {@code majorVersion} could be built from different repositories. The value is
 * {@code <language>:<majorVersion>:<repo>=<id>[;<id>…]} CSV, e.g.
 * {@code java:3:aws-database-encryption-sdk-dynamodb=some-bug;another-bug} (read
 * from the system property first, then the {@code TESTSERVER_KNOWN_BUGS}
 * environment variable).
 *
 * <p>Unlike Feature support, absence here is <em>not</em> a configuration error:
 * a bug a target does not declare is simply not exhibited, so
 * {@link #exhibits(String, int, String, String)} returns {@code false} for an
 * unconfigured registry, an undeclared target, or an undeclared id — the
 * assertion then runs with its full power to fail. This is the normal case (no
 * bug), which is why it is never treated as missing configuration.
 */
public final class KnownBugDeclarations {

    /** Runtime-config key: comma-separated {@code language:major:repo=id[;id…]} entries. */
    public static final String KNOWN_BUGS_PROPERTY = "testserver.knownBugs";
    public static final String KNOWN_BUGS_ENV = "TESTSERVER_KNOWN_BUGS";

    private static volatile KnownBugDeclarations instance;

    /** (language:major:repo) -> the bug ids that source declares it exhibits. */
    private final Map<String, Set<String>> byTarget;

    private KnownBugDeclarations(Map<String, Set<String>> byTarget) {
        this.byTarget = byTarget;
    }

    /** The canonical registry key for a target's source identity. */
    private static String key(String language, int majorVersion, String repo) {
        return language + ":" + majorVersion + ":" + repo;
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
     * Parse the {@code language:major:repo=id[;id…]} CSV into a registry.
     * {@code null} or blank means "no known bug declared" — an empty registry.
     * Public so per-SDK unit tests can exercise parsing without the JVM-wide
     * singleton or system properties.
     */
    public static KnownBugDeclarations parse(String raw) {
        Map<String, Set<String>> byTarget = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return new KnownBugDeclarations(byTarget);
        }
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException(
                    "malformed known-bug entry (expected language:major:repo=id[;id...]): "
                        + trimmed);
            }
            String[] parts = trimmed.substring(0, eq).trim().split(":");
            if (parts.length != 3 || parts[0].trim().isEmpty()
                    || parts[1].trim().isEmpty() || parts[2].trim().isEmpty()) {
                throw new IllegalArgumentException(
                    "malformed known-bug key (expected language:major:repo): "
                        + trimmed.substring(0, eq).trim());
            }
            int majorVersion;
            try {
                majorVersion = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                    "major version must be an integer in known-bug key: " + trimmed, e);
            }
            String canonicalKey = key(parts[0].trim(), majorVersion, parts[2].trim());
            if (byTarget.containsKey(canonicalKey)) {
                throw new IllegalArgumentException(
                    "duplicate target in " + KNOWN_BUGS_PROPERTY + ": " + canonicalKey);
            }
            Set<String> ids = new LinkedHashSet<>();
            for (String id : trimmed.substring(eq + 1).split(";")) {
                String name = id.trim();
                if (name.isEmpty()) {
                    continue;
                }
                if (!ids.add(name)) {
                    throw new IllegalArgumentException(
                        "duplicate bug id '" + name + "' declared for target '" + canonicalKey + "'");
                }
            }
            if (ids.isEmpty()) {
                throw new IllegalArgumentException(
                    "target '" + canonicalKey + "' declares no bug ids in " + KNOWN_BUGS_PROPERTY);
            }
            byTarget.put(canonicalKey, ids);
        }
        return new KnownBugDeclarations(byTarget);
    }

    /**
     * @return whether the source {@code (language, majorVersion, repo)} declares
     *     it exhibits the bug {@code id}. {@code false} when the registry is
     *     empty, the target is absent, or the id is not among that target's
     *     declared ids — a bug not declared is simply not exhibited.
     */
    public boolean exhibits(String language, int majorVersion, String repo, String id) {
        Set<String> ids = byTarget.get(key(language, majorVersion, repo));
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
