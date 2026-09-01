package aws.cryptography.esdk.testserver.tests;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The per-server known-bug sets: for each Language_Server {@link Target}, the
 * set of catalogued bug ids that server currently <em>exhibits</em> — wrong
 * behavior a Test correctly fails, not missing capability (a missing capability
 * is a Feature_Declaration concern, {@link FeatureDeclarations}).
 *
 * <p>There is <b>no central ledger</b>. Each Language_Server declares the bugs
 * it exhibits in its own repository's {@code bug-configuration.json} (a flat
 * array of bug ids); a language with no repository (Python) declares them inline
 * in the Configuration_Set. The orchestrator resolves those per target and hands
 * the Tests {@value #PROPERTY} (mirroring {@code esdk.testserver.features}) — a
 * server absent from the property, or with an empty set, exhibits no bug.
 *
 * <p>{@link KnownBugGate} consults these under expected-failure semantics: a
 * Target that declares a bug tolerates exactly the assertion that bug breaks;
 * any other Target asserts live. Because the set is authoritative and
 * per-server, fixing a bug is simply removing its id from that server's
 * {@code bug-configuration.json} — no reconciliation and no central set to keep
 * in step.
 */
public final class KnownBugs {

    /**
     * Runtime-config key carrying the orchestrator-resolved per-server known
     * bugs: a comma-separated list of
     * {@code <language>:<majorVersion>:<repository>=<id>[;<id>…]} entries, e.g.
     * {@code rust:1:aws-crypto-tools-rust=encrypt-non-positive-frame-length-generic-error}.
     * Each id is a bug that Target exhibits. Absent means no server declared a bug.
     */
    public static final String PROPERTY = "esdk.testserver.knownBugs";
    public static final String ENV = "ESDK_TESTSERVER_KNOWN_BUGS";

    private static volatile KnownBugs instance;

    /** Target -> the bug ids it exhibits, in declared order. */
    private final Map<Target, Set<String>> byTarget;

    /** One Language_Server identity a bug is declared against. */
    record Target(String language, int majorVersion, String repository) {
        Target {
            if (language == null || language.isBlank()) {
                throw new IllegalArgumentException("known-bug target language must be non-blank");
            }
            if (repository == null || repository.isBlank()) {
                throw new IllegalArgumentException(
                    "known-bug target repository must be non-blank (language '" + language + "')");
            }
            if (majorVersion < 1) {
                throw new IllegalArgumentException(
                    "known-bug target majorVersion must be >= 1, was " + majorVersion
                        + " (language '" + language + "')");
            }
        }

        /** The {@code <language>-v<majorVersion> in <repository>} label used in messages. */
        String label() {
            return language + "-v" + majorVersion + " in " + repository;
        }
    }

    private KnownBugs(Map<Target, Set<String>> byTarget) {
        this.byTarget = byTarget;
    }

    /** @return the process-wide sets, resolved from {@value #PROPERTY} on first access. */
    public static KnownBugs shared() {
        KnownBugs local = instance;
        if (local == null) {
            synchronized (KnownBugs.class) {
                local = instance;
                if (local == null) {
                    local = parse(configured());
                    instance = local;
                }
            }
        }
        return local;
    }

    /** @return whether {@code target} declares {@code bugId} among its known bugs. */
    boolean exhibits(Target target, String bugId) {
        return byTarget.getOrDefault(target, Set.of()).contains(bugId);
    }

    /** @return the bug ids {@code target} declares, in declared order (empty when none). */
    Set<String> bugsFor(Target target) {
        return byTarget.getOrDefault(target, Set.of());
    }

    /**
     * Parse the {@value #PROPERTY} value ({@code null} or blank = no server
     * declared a bug). Package-private so unit tests can exercise parsing
     * without the JVM-wide singleton or system properties. A malformed entry —
     * a key that is not a {@code language:major:repository} triple, a
     * non-integer major, a duplicate target, or a duplicate id within a target —
     * is an {@link IllegalArgumentException}, since the orchestrator generates
     * this value from validated configuration.
     */
    static KnownBugs parse(String raw) {
        Map<Target, Set<String>> byTarget = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return new KnownBugs(byTarget);
        }
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException(
                    "malformed known-bug entry (expected language:major:repository=id[;id...]): "
                        + trimmed);
            }
            Target target = parseTarget(trimmed.substring(0, eq).trim());
            if (byTarget.containsKey(target)) {
                throw new IllegalArgumentException(
                    "duplicate target in " + PROPERTY + ": " + target.label());
            }
            Set<String> ids = new LinkedHashSet<>();
            for (String idToken : trimmed.substring(eq + 1).split(";")) {
                String bugId = idToken.trim();
                if (bugId.isEmpty()) {
                    continue;
                }
                if (!ids.add(bugId)) {
                    throw new IllegalArgumentException(
                        "duplicate bug id '" + bugId + "' declared for " + target.label());
                }
            }
            byTarget.put(target, ids);
        }
        return new KnownBugs(byTarget);
    }

    /** Parse a {@code language:major:repository} key, throwing on malformed input. */
    private static Target parseTarget(String key) {
        String[] parts = key.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException(
                "malformed known-bug target key (expected language:major:repository): " + key);
        }
        int majorVersion;
        try {
            majorVersion = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "known-bug target major version is not an integer: " + key, e);
        }
        return new Target(parts[0].trim(), majorVersion, parts[2].trim());
    }

    private static String configured() {
        String fromProperty = System.getProperty(PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return System.getenv(ENV);
    }
}
