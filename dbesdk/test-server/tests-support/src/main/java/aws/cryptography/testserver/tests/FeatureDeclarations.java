package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The runtime Feature_Declaration registry the {@code Tests} consult when gating
 * Feature-associated Tests (Requirement 9.3), resolved once per JVM from
 * <em>runtime configuration only</em> and shared across every test class —
 * mirroring {@link LanguageServerRegistry}.
 *
 * <p>Feature support and raw-RSA padding capability are keyed by the full
 * {@code (language, majorVersion, repo)} source identity — the same tuple the
 * targets ({@link LanguageServerRegistry}) and known-bug
 * ({@link KnownBugDeclarations}) registries use — because a capability may
 * differ between two sources that share a language (a different major version,
 * or the same library built from a different repository).
 *
 * <p>Two runtime properties feed the registry (each read from the system
 * property first, then the environment variable):
 * <ol>
 *   <li><b>{@code testserver.features} / {@code TESTSERVER_FEATURES}</b> —
 *       a comma-separated list of per-source declarations, each of the form
 *       {@code <language>:<majorVersion>:<repo>:<feature>=<bool>[;<feature>=<bool>…]}
 *       (e.g. {@code java:3:aws-database-encryption-sdk-dynamodb:streaming=true;MPL=true}).
 *       The orchestrator derives this by flattening each source's
 *       Feature_Declaration: a Feature in {@code supportedFeatures} becomes
 *       {@code true}, one in {@code unsupportedFeatures} becomes {@code false}.</li>
 *   <li><b>{@code testserver.featureCatalog} /
 *       {@code TESTSERVER_FEATURE_CATALOG}</b> — the commons configuration's
 *       Feature_Catalog verbatim, as a comma-separated list of Feature names
 *       (e.g. {@code raw-aes,aws-kms}).</li>
 * </ol>
 *
 * <p>A third, <em>optional</em> property carries the per-source raw-RSA
 * padding capability: <b>{@code testserver.rawRsaPaddingSchemes} /
 * {@code TESTSERVER_RAW_RSA_PADDING_SCHEMES}</b> — a comma-separated list
 * of {@code <language>:<majorVersion>:<repo>:<SCHEME>[;<SCHEME>…]} entries (e.g.
 * {@code c:1:some-repo:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1}), one per source
 * whose Feature_Declaration carries {@code rawRsaPaddingSchemes}. Unlike Feature
 * support, absence here is itself a declaration: a source absent from the
 * property (or the property absent entirely) declared no restriction, so it
 * supports every scheme names — that is the capability's
 * absent-means-all semantic transmitted from the configuration, not an
 * assumption. Scheme names must be values of the modeled scheme names;
 * anything else is a parse error.
 *
 * <p>Support is determined <em>solely</em> from the declarations: an absent
 * property, an absent source, or an absent {@code (source, Feature)} pair is
 * a <b>configuration error</b> surfaced when queried ({@link IllegalStateException}
 * with an actionable message) — support is never assumed (Requirement 9.3).
 * Boolean values must be exactly {@code true} or {@code false}; anything else is
 * a parse error, never coerced.
 */
public final class FeatureDeclarations {

    /**
     * Runtime-config key: comma-separated
     * {@code lang:major:repo:feat=bool[;feat=bool…]} entries.
     */
    public static final String FEATURES_PROPERTY = "testserver.features";
    public static final String FEATURES_ENV = "TESTSERVER_FEATURES";

    /** Runtime-config key: comma-separated Feature_Catalog names. */
    public static final String CATALOG_PROPERTY = "testserver.featureCatalog";
    public static final String CATALOG_ENV = "TESTSERVER_FEATURE_CATALOG";

    /** Runtime-config key: comma-separated {@code lang:major:repo:SCHEME[;SCHEME…]} entries. */
    public static final String RAW_RSA_PADDING_SCHEMES_PROPERTY =
        "testserver.rawRsaPaddingSchemes";
    public static final String RAW_RSA_PADDING_SCHEMES_ENV =
        "TESTSERVER_RAW_RSA_PADDING_SCHEMES";

    private static volatile FeatureDeclarations instance;

    /** Catalog names in configuration order; {@code null} when unconfigured. */
    private final List<String> catalog;

    /**
     * {@code language:major:repo} source key -> (feature -> supported);
     * {@code null} when unconfigured.
     */
    private final Map<String, Map<String, Boolean>> declarations;

    /**
     * {@code language:major:repo} source key -> declared raw-RSA padding
     * schemes, only for sources that declared the capability; never
     * {@code null} (absence means "no source declared a restriction", not
     * "unconfigured").
     */
    private final Map<String, Set<String>> rawRsaPaddingSchemes;

    private FeatureDeclarations(List<String> catalog, Map<String, Map<String, Boolean>> declarations,
            Map<String, Set<String>> rawRsaPaddingSchemes) {
        this.catalog = catalog;
        this.declarations = declarations;
        this.rawRsaPaddingSchemes = rawRsaPaddingSchemes;
    }

    /** The composite source key {@code language:majorVersion:repo}. */
    private static String key(String language, int majorVersion, String repo) {
        return language + ":" + majorVersion + ":" + repo;
    }

    /**
     * @return the process-wide registry, resolving the two runtime properties on
     *     first access (once per JVM). Resolution never fails on <em>absent</em>
     *     configuration — absence surfaces as a configuration error only when the
     *     registry is queried — but a <em>malformed</em> property fails here.
     */
    public static FeatureDeclarations shared() {
        FeatureDeclarations local = instance;
        if (local == null) {
            synchronized (FeatureDeclarations.class) {
                local = instance;
                if (local == null) {
                    local = parse(
                        configuredValue(FEATURES_PROPERTY, FEATURES_ENV),
                        configuredValue(CATALOG_PROPERTY, CATALOG_ENV),
                        configuredValue(
                            RAW_RSA_PADDING_SCHEMES_PROPERTY, RAW_RSA_PADDING_SCHEMES_ENV));
                    instance = local;
                }
            }
        }
        return local;
    }

    /**
     * Parse raw property values into a registry. {@code null} or blank raws mean
     * "unconfigured" — the corresponding queries fail with a configuration error.
     * Public because per-SDK unit tests, which live in a different package
     * than this class, exercise parsing without touching the JVM-wide
     * singleton or system properties.
     */
    /** {@link #parse(String, String, String)} with no padding property configured. */
    public static FeatureDeclarations parse(String featuresRaw, String catalogRaw) {
        return parse(featuresRaw, catalogRaw, null);
    }

    public static FeatureDeclarations parse(String featuresRaw, String catalogRaw, String paddingsRaw) {
        List<String> catalog = isBlank(catalogRaw) ? null : parseCatalog(catalogRaw);
        Map<String, Map<String, Boolean>> declarations =
            isBlank(featuresRaw) ? null : parseDeclarations(featuresRaw);
        Map<String, Set<String>> rawRsaPaddingSchemes =
            isBlank(paddingsRaw) ? Map.of() : parseRawRsaPaddingSchemes(paddingsRaw);
        return new FeatureDeclarations(catalog, declarations, rawRsaPaddingSchemes);
    }

    /**
     * @return whether the {@code (language, majorVersion, repo)} source declares
     *     {@code feature} supported, determined solely from the parsed
     *     Feature_Declarations.
     * @throws IllegalStateException if no declarations were configured, the
     *     source has no declaration, or the {@code (source, feature)} pair is
     *     absent — a configuration error, never an assumption (Requirement 9.3).
     */
    public boolean isSupported(String language, int majorVersion, String repo, String feature) {
        Map<String, Map<String, Boolean>> declared = requireDeclarations();
        String sourceKey = key(language, majorVersion, repo);
        Map<String, Boolean> byFeature = declared.get(sourceKey);
        if (byFeature == null) {
            throw new IllegalStateException(
                "configuration error: no Feature_Declaration for source '" + sourceKey
                    + "' in " + FEATURES_PROPERTY + " (declared sources: " + declared.keySet()
                    + "); Feature support is never assumed");
        }
        Boolean supported = byFeature.get(feature);
        if (supported == null) {
            throw new IllegalStateException(
                "configuration error: source '" + sourceKey + "' declares no support value for Feature '"
                    + feature + "' in " + FEATURES_PROPERTY + " (declared Features: " + byFeature.keySet()
                    + "); Feature support is never assumed");
        }
        return supported;
    }

    /**
     * @return whether per-source Feature_Declarations were configured for this
     *     run. False in an unconfigured run (e.g. an offline single-server smoke
     *     check with no {@value #FEATURES_PROPERTY}); callers that filter pairs by
     *     capability degrade to no filtering rather than fail.
     */
    public boolean isConfigured() {
        return declarations != null;
    }

    /**
     * @return whether the {@code (language, majorVersion, repo)} source supports
     *     the raw-RSA padding {@code scheme}. A source absent from the
     *     {@value #RAW_RSA_PADDING_SCHEMES_PROPERTY} property (or the property
     *     absent entirely) declared no restriction — its Feature_Declaration
     *     carries no {@code rawRsaPaddingSchemes} — so every scheme is
     *     supported; a present source supports exactly its declared subset.
     */
    public boolean supportsRawRsaPadding(String language, int majorVersion, String repo, String scheme) {
        Set<String> declared = rawRsaPaddingSchemes.get(key(language, majorVersion, repo));
        return declared == null || declared.contains(scheme);
    }

    /**
     * @return the Feature_Catalog names, in configuration order.
     * @throws IllegalStateException if no catalog was configured.
     */
    public List<String> catalog() {
        if (catalog == null) {
            throw new IllegalStateException(
                "configuration error: no Feature_Catalog configured; set -D" + CATALOG_PROPERTY
                    + "=<feature,feature,...> (or " + CATALOG_ENV + ")");
        }
        return catalog;
    }

    /**
     * @return the {@code language:major:repo} source keys carrying a
     *     Feature_Declaration, in configuration order.
     * @throws IllegalStateException if no declarations were configured.
     */
    public Set<String> sources() {
        return requireDeclarations().keySet();
    }

    private Map<String, Map<String, Boolean>> requireDeclarations() {
        if (declarations == null) {
            throw new IllegalStateException(
                "configuration error: no Feature_Declarations configured; set -D" + FEATURES_PROPERTY
                    + "=<lang:major:repo:feat=bool[;feat=bool...]>,... (or " + FEATURES_ENV + ")");
        }
        return declarations;
    }

    private static String configuredValue(String property, String env) {
        String fromProperty = System.getProperty(property);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return System.getenv(env);
    }

    private static boolean isBlank(String raw) {
        return raw == null || raw.isBlank();
    }

    /** Parse the Feature-name CSV, preserving order and rejecting duplicates. */
    private static List<String> parseCatalog(String raw) {
        Set<String> names = new LinkedHashSet<>();
        for (String token : raw.split(",")) {
            String name = token.trim();
            if (name.isEmpty()) {
                continue;
            }
            if (!names.add(name)) {
                throw new IllegalArgumentException(
                    "duplicate Feature name in " + CATALOG_PROPERTY + ": " + name);
            }
        }
        if (names.isEmpty()) {
            throw new IllegalArgumentException(
                "no Feature names parsed from " + CATALOG_PROPERTY + ": " + raw);
        }
        return List.copyOf(new ArrayList<>(names));
    }

    /**
     * Parse {@code lang:major:repo:feat=bool[;feat=bool…]} CSV entries, keyed by
     * the {@code (language, majorVersion, repo)} source identity, rejecting
     * duplicates. The feature list is split off with {@code split(":", 4)} — a
     * feature declaration ({@code feat=bool}) contains no colon, so the fourth
     * segment is the whole list.
     */
    private static Map<String, Map<String, Boolean>> parseDeclarations(String raw) {
        Map<String, Map<String, Boolean>> bySource = new LinkedHashMap<>();
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] parts = trimmed.split(":", 4);
            if (parts.length != 4) {
                throw new IllegalArgumentException(
                    "malformed declaration entry (expected "
                        + "language:major:repo:feature=bool[;feature=bool...]): " + trimmed);
            }
            String language = parts[0].trim();
            String repo = parts[2].trim();
            if (language.isEmpty() || repo.isEmpty()) {
                throw new IllegalArgumentException(
                    "blank language or repo in declaration entry: " + trimmed);
            }
            int majorVersion = parseMajor(parts[1].trim(), trimmed);
            String sourceKey = key(language, majorVersion, repo);
            if (bySource.containsKey(sourceKey)) {
                throw new IllegalArgumentException(
                    "duplicate source in " + FEATURES_PROPERTY + ": " + sourceKey);
            }
            bySource.put(sourceKey, parseSourceDeclarations(sourceKey, parts[3]));
        }
        if (bySource.isEmpty()) {
            throw new IllegalArgumentException(
                "no declarations parsed from " + FEATURES_PROPERTY + ": " + raw);
        }
        return bySource;
    }

    private static Map<String, Boolean> parseSourceDeclarations(String sourceKey, String rawDeclarations) {
        Map<String, Boolean> byFeature = new LinkedHashMap<>();
        for (String declaration : rawDeclarations.split(";")) {
            String trimmed = declaration.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException(
                    "malformed feature declaration for source '" + sourceKey
                        + "' (expected feature=bool): " + trimmed);
            }
            String feature = trimmed.substring(0, eq).trim();
            if (feature.isEmpty()) {
                throw new IllegalArgumentException(
                    "blank Feature name for source '" + sourceKey + "': " + trimmed);
            }
            String value = trimmed.substring(eq + 1).trim();
            Boolean supported = switch (value) {
                case "true" -> Boolean.TRUE;
                case "false" -> Boolean.FALSE;
                default -> throw new IllegalArgumentException(
                    "feature support value must be exactly 'true' or 'false' for source '"
                        + sourceKey + "', Feature '" + feature + "': " + value);
            };
            if (byFeature.putIfAbsent(feature, supported) != null) {
                throw new IllegalArgumentException(
                    "duplicate Feature '" + feature + "' declared for source '" + sourceKey + "'");
            }
        }
        if (byFeature.isEmpty()) {
            throw new IllegalArgumentException(
                "source '" + sourceKey + "' declares no features in " + FEATURES_PROPERTY);
        }
        return byFeature;
    }

    /**
     * Parse {@code lang:major:repo:SCHEME[;SCHEME…]} CSV entries, keyed by the
     * {@code (language, majorVersion, repo)} source identity, rejecting duplicate
     * sources, duplicate schemes, and empty scheme lists. Scheme names are opaque
     * strings here: each SDK's Tests validate them against its own modeled scheme
     * enum in a per-SDK layer above this parser.
     */
    private static Map<String, Set<String>> parseRawRsaPaddingSchemes(String raw) {
        Map<String, Set<String>> bySource = new LinkedHashMap<>();
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] parts = trimmed.split(":", 4);
            if (parts.length != 4) {
                throw new IllegalArgumentException(
                    "malformed padding entry (expected language:major:repo:SCHEME[;SCHEME...]): "
                        + trimmed);
            }
            String language = parts[0].trim();
            String repo = parts[2].trim();
            if (language.isEmpty() || repo.isEmpty()) {
                throw new IllegalArgumentException("blank language or repo in padding entry: " + trimmed);
            }
            int majorVersion = parseMajor(parts[1].trim(), trimmed);
            String sourceKey = key(language, majorVersion, repo);
            if (bySource.containsKey(sourceKey)) {
                throw new IllegalArgumentException(
                    "duplicate source in " + RAW_RSA_PADDING_SCHEMES_PROPERTY + ": " + sourceKey);
            }
            Set<String> schemes = new LinkedHashSet<>();
            for (String scheme : parts[3].split(";")) {
                String name = scheme.trim();
                if (name.isEmpty()) {
                    continue;
                }
                if (!schemes.add(name)) {
                    throw new IllegalArgumentException(
                        "duplicate raw-RSA padding scheme '" + name + "' declared for source '"
                            + sourceKey + "'");
                }
            }
            if (schemes.isEmpty()) {
                throw new IllegalArgumentException(
                    "source '" + sourceKey + "' declares no padding schemes in "
                        + RAW_RSA_PADDING_SCHEMES_PROPERTY);
            }
            bySource.put(sourceKey, schemes);
        }
        if (bySource.isEmpty()) {
            throw new IllegalArgumentException(
                "no padding declarations parsed from " + RAW_RSA_PADDING_SCHEMES_PROPERTY
                    + ": " + raw);
        }
        return bySource;
    }

    private static int parseMajor(String raw, String entry) {
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "non-integer major version '" + raw + "' in entry: " + entry, e);
        }
    }
}
