package aws.cryptography.testserver.tests;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The set of Language_Server {@link LanguageServerTarget}s the {@code Tests} drive,
 * resolved once from <em>runtime configuration only</em> and shared across every
 * test class as a process-wide singleton.
 *
 * <p>The Tests are <strong>endpoint-only</strong> (Requirement 10.2): each Target
 * is located exclusively through the endpoint supplied at run time via
 * <b>{@code testserver.targets}</b> (system property) or
 * <b>{@code TESTSERVER_TARGETS}</b> (environment variable) — a
 * comma-separated list of {@code <language>:<majorVersion>:<repo>=<endpointUrl>} entries
 * (e.g. {@code java:3=http://127.0.0.1:8091,python:4=http://127.0.0.1:8092}).
 * The orchestrator launches every configured Language_Server and supplies this
 * property; there is no managed (in-process) fallback and no legacy endpoint
 * property. When nothing is configured, resolution fails with an actionable
 * message rather than assuming any server.
 *
 * <p>The cross-language matrix ({@link #pairs()}) is the full pairwise product of
 * targets on the encrypt and decrypt legs, <em>including</em> same-target pairs
 * (e.g. {@code java-v3 -> java-v3}) for completeness. Meta (harness-plumbing)
 * Tests run against the {@link #primary()} configured target only.
 */
public final class LanguageServerRegistry {

    /** Runtime-config key: comma-separated {@code language:major:repo=url} target entries. */
    public static final String TARGETS_PROPERTY = "testserver.targets";
    public static final String TARGETS_ENV = "TESTSERVER_TARGETS";

    private static volatile LanguageServerRegistry instance;

    private final List<LanguageServerTarget> targets;

    private LanguageServerRegistry(List<LanguageServerTarget> targets) {
        this.targets = List.copyOf(targets);
    }

    /**
     * @return the process-wide registry, resolving the configured targets on
     *     first access. Safe to call from a static {@code @MethodSource} — it
     *     does not depend on JUnit lifecycle callbacks.
     * @throws IllegalStateException when no targets are configured (the Tests
     *     are endpoint-only; there is no managed fallback)
     */
    public static LanguageServerRegistry shared() {
        LanguageServerRegistry local = instance;
        if (local == null) {
            synchronized (LanguageServerRegistry.class) {
                local = instance;
                if (local == null) {
                    local = resolve();
                    instance = local;
                }
            }
        }
        return local;
    }

    private static LanguageServerRegistry resolve() {
        String configured = configuredTargets().orElseThrow(() -> new IllegalStateException(
            "No Language_Server targets configured. The Tests are endpoint-only "
                + "(Requirement 10.2): supply the targets via the -D" + TARGETS_PROPERTY
                + " system property or the " + TARGETS_ENV + " environment variable as a "
                + "comma-separated list of <language>:<majorVersion>:<repo>=<endpointUrl> entries, "
                + "e.g. -D" + TARGETS_PROPERTY
                + "=java:3=http://127.0.0.1:8091,python:4=http://127.0.0.1:8092. "
                + "Run the Tests through the orchestrated entry point (`make orchestrate`), "
                + "which launches every configured Language_Server and supplies this property."));
        return new LanguageServerRegistry(parseTargets(configured));
    }

    /**
     * Parse a raw {@code testserver.targets} value into a registry without
     * touching the process-wide singleton, system properties, or the
     * environment. Public because per-SDK unit tests, which live in a
     * different package than this class, exercise the parser directly (e.g.
     * the Property 12 jqwik test round-trips format→parse and drives the
     * pairwise matrix through it).
     */
    public static LanguageServerRegistry parse(String raw) {
        return new LanguageServerRegistry(parseTargets(raw));
    }

    private static Optional<String> configuredTargets() {
        String property = System.getProperty(TARGETS_PROPERTY);
        if (property != null && !property.isBlank()) {
            return Optional.of(property);
        }
        String env = System.getenv(TARGETS_ENV);
        if (env != null && !env.isBlank()) {
            return Optional.of(env);
        }
        return Optional.empty();
    }

    /**
     * Parse {@code language:major:repo=url} entries into targets, preserving order and
     * rejecting duplicates of the same {@code (language, majorVersion)} tuple.
     */
    private static List<LanguageServerTarget> parseTargets(String raw) {
        Map<String, LanguageServerTarget> byIdentity = new LinkedHashMap<>();
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException(
                    "malformed target entry (expected language:major:repo=url): " + trimmed);
            }
            String key = trimmed.substring(0, eq).trim();
            String url = trimmed.substring(eq + 1).trim();
            String[] parts = key.split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException(
                    "malformed target key (expected language:major:repo): " + key);
            }
            String language = parts[0].trim();
            int majorVersion;
            try {
                majorVersion = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("major version must be an integer: " + key, e);
            }
            String repo = parts[2].trim();
            LanguageServerTarget target =
                new LanguageServerTarget(language, majorVersion, repo, URI.create(url));
            String identity = language + ":" + majorVersion + ":" + repo;
            if (byIdentity.putIfAbsent(identity, target) != null) {
                throw new IllegalArgumentException("duplicate target: " + identity);
            }
        }
        if (byIdentity.isEmpty()) {
            throw new IllegalArgumentException("no valid targets parsed from: " + raw);
        }
        return new ArrayList<>(byIdentity.values());
    }

    /** @return all configured targets, in configuration order. */
    public List<LanguageServerTarget> targets() {
        return targets;
    }

    /**
     * @return the first configured target — the primary. Meta (harness-plumbing)
     *     Tests run against this target only.
     */
    public LanguageServerTarget primary() {
        return targets.get(0);
    }

    /** @return the primary target paired with itself, for single-server Tests. */
    public TargetPair selfPair() {
        LanguageServerTarget primary = primary();
        return new TargetPair(primary, primary);
    }

    /**
     * @return the full pairwise cross-language matrix: every {@code (encrypt,
     *     decrypt)} target pair, including same-target pairs. With a single target
     *     this is one self-pair.
     */
    public List<TargetPair> pairs() {
        List<TargetPair> pairs = new ArrayList<>(targets.size() * targets.size());
        for (LanguageServerTarget encrypt : targets) {
            for (LanguageServerTarget decrypt : targets) {
                pairs.add(new TargetPair(encrypt, decrypt));
            }
        }
        return pairs;
    }
}
