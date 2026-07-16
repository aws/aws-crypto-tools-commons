package aws.cryptography.esdk.testserver.tests;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The set of Language_Server {@link LanguageServerTarget}s the {@code Tests} drive,
 * resolved once from <em>runtime configuration only</em> (Requirement 7.3) and
 * shared across every test class as a process-wide singleton.
 *
 * <p>Resolution precedence:
 * <ol>
 *   <li><b>{@code esdk.testserver.targets} / {@code ESDK_TESTSERVER_TARGETS}</b> — a
 *       comma-separated list of {@code <language>:<majorVersion>=<endpointUrl>}
 *       entries (e.g. {@code java:3=http://127.0.0.1:8080,python:4=http://127.0.0.1:8081}).
 *       This is what the orchestrator supplies when it launches multiple servers.</li>
 *   <li><b>{@code esdk.testserver.endpoints}</b> (legacy, {@link RuntimeEndpointConfig}) —
 *       one or more bare URLs, mapped to {@code (java, 3, url)} targets so the
 *       existing single-endpoint {@code make test-live} flow keeps working.</li>
 *   <li><b>Managed</b> — nothing configured: boot ONE Java Language_Server
 *       in-process on an ephemeral port and expose it as the single {@code
 *       (java, 3)} target. A JVM shutdown hook stops it.</li>
 * </ol>
 *
 * <p>The cross-language matrix ({@link #pairs()}) is the full pairwise product of
 * targets on the encrypt and decrypt legs, <em>including</em> same-target pairs
 * (e.g. {@code java-v3 -> java-v3}) for completeness. With only Java configured
 * (managed / legacy) the matrix is the single {@code java-v3 -> java-v3} pair, so
 * the existing Tests reduce to their previous behavior.
 */
public final class LanguageServerRegistry {

    /** Runtime-config key: comma-separated {@code language:major=url} target entries. */
    public static final String TARGETS_PROPERTY = "esdk.testserver.targets";
    public static final String TARGETS_ENV = "ESDK_TESTSERVER_TARGETS";

    /** Default language/major version for the managed and legacy-endpoint modes. */
    private static final String DEFAULT_LANGUAGE = "java";
    private static final int DEFAULT_MAJOR_VERSION = 3;

    /**
     * Languages whose Language_Server drives the ESDK <em>streaming</em> API
     * (Streaming_Capable). The stream round-trip only runs over a pair when BOTH
     * endpoints are streaming-capable (Requirements 4.9, 4.10). Java is
     * streaming-capable; the hand-implemented Python server is too.
     */
    private static final Set<String> STREAMING_CAPABLE_LANGUAGES = Set.of("java", "python");

    private static volatile LanguageServerRegistry instance;

    private final List<LanguageServerTarget> targets;
    private final LocalJavaLanguageServer managedServer; // null unless managed mode booted one

    private LanguageServerRegistry(List<LanguageServerTarget> targets, LocalJavaLanguageServer managedServer) {
        this.targets = List.copyOf(targets);
        this.managedServer = managedServer;
    }

    /**
     * @return the process-wide registry, resolving configuration (and booting a
     *     managed Java server if nothing is configured) on first access. Safe to
     *     call from a static {@code @MethodSource} — it does not depend on JUnit
     *     lifecycle callbacks.
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
        Optional<String> configured = configuredTargets();
        if (configured.isPresent()) {
            return new LanguageServerRegistry(parseTargets(configured.get()), null);
        }
        List<String> legacyEndpoints = RuntimeEndpointConfig.fromRuntime().endpoints();
        if (!legacyEndpoints.isEmpty()) {
            // Legacy single-language mode: map the configured endpoint(s) to the
            // default (java, 3) target. Only the first distinct endpoint is used as
            // the java-v3 target; the historical enc/dec split collapses to one
            // server target (matching how make test-live points at one server).
            URI endpoint = URI.create(legacyEndpoints.get(0));
            return new LanguageServerRegistry(
                List.of(new LanguageServerTarget(DEFAULT_LANGUAGE, DEFAULT_MAJOR_VERSION, endpoint)), null);
        }
        // Managed mode: boot one Java server in-process and stop it at JVM exit.
        LocalJavaLanguageServer server = LocalJavaLanguageServer.start();
        LanguageServerTarget target =
            new LanguageServerTarget(DEFAULT_LANGUAGE, DEFAULT_MAJOR_VERSION, server.endpoint());
        Runtime.getRuntime().addShutdownHook(new Thread(server::close, "esdk-managed-server-shutdown"));
        return new LanguageServerRegistry(List.of(target), server);
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
     * Parse {@code language:major=url} entries into targets, preserving order and
     * rejecting duplicates of the same {@code (language, majorVersion)} tuple.
     */
    private static List<LanguageServerTarget> parseTargets(String raw) {
        Map<String, LanguageServerTarget> byLabel = new LinkedHashMap<>();
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException(
                    "malformed target entry (expected language:major=url): " + trimmed);
            }
            String langVer = trimmed.substring(0, eq).trim();
            String url = trimmed.substring(eq + 1).trim();
            int colon = langVer.indexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException(
                    "malformed target key (expected language:major): " + langVer);
            }
            String language = langVer.substring(0, colon).trim();
            int majorVersion;
            try {
                majorVersion = Integer.parseInt(langVer.substring(colon + 1).trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("major version must be an integer: " + langVer, e);
            }
            LanguageServerTarget target =
                new LanguageServerTarget(language, majorVersion, URI.create(url));
            if (byLabel.putIfAbsent(target.label(), target) != null) {
                throw new IllegalArgumentException("duplicate target: " + target.label());
            }
        }
        if (byLabel.isEmpty()) {
            throw new IllegalArgumentException("no valid targets parsed from: " + raw);
        }
        return new ArrayList<>(byLabel.values());
    }

    /** @return all configured targets, in configuration order. */
    public List<LanguageServerTarget> targets() {
        return targets;
    }

    /** @return the first configured target (used by single-server Tests). */
    public LanguageServerTarget primary() {
        return targets.get(0);
    }

    /** @return the primary target paired with itself, for single-server Tests. */
    public EndpointPair selfPair() {
        LanguageServerTarget primary = primary();
        return new EndpointPair(primary, primary);
    }

    /**
     * @return the full pairwise cross-language matrix: every {@code (encrypt,
     *     decrypt)} target pair, including same-target pairs. With a single target
     *     this is one self-pair.
     */
    public List<EndpointPair> pairs() {
        List<EndpointPair> pairs = new ArrayList<>(targets.size() * targets.size());
        for (LanguageServerTarget encrypt : targets) {
            for (LanguageServerTarget decrypt : targets) {
                pairs.add(new EndpointPair(encrypt, decrypt));
            }
        }
        return pairs;
    }

    /** @return {@code true} when {@code target}'s language drives the ESDK streaming API. */
    public static boolean isStreamingCapable(LanguageServerTarget target) {
        return STREAMING_CAPABLE_LANGUAGES.contains(target.language());
    }
}
