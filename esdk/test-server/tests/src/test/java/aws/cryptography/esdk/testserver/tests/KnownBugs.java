package aws.cryptography.esdk.testserver.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The known-bug ledger: catalogued, reproduced BUGS in the ESDK implementations
 * under test — wrong behavior a Test correctly fails, not missing capability (a
 * missing capability is a Feature_Declaration concern, {@link FeatureDeclarations}).
 *
 * <p>The ledger has the same two-layer shape as the Feature_Declarations: a
 * committed <em>base</em> ledger loaded from {@value #RESOURCE} in this module,
 * and per-Language_Repository <em>overrides</em> the orchestrator resolves from
 * each repository's commons-configuration file and hands the Tests via
 * {@value #OVERRIDES_PROPERTY} (mirroring {@code esdk.testserver.features}). A
 * repository speaks only for its own {@link Target}: an override marks a bug
 * {@code present} (this target exhibits a bug the base ledger did not record for
 * it) or {@code absent} (this target no longer exhibits a base-declared bug —
 * the fix is landing). This makes the "PR the override red, then fix it green"
 * workflow possible: a language repository removes its own exception, the gated
 * row starts failing, and the fix turns it green.
 *
 * <p>Each entry carries a stable {@code id}, a one-line {@code description} of
 * the wrong behavior, and the {@link Target}s exhibiting it — the
 * {@code (language, majorVersion, repository)} triples, not bare languages, so
 * two servers of the same language from different repositories or major versions
 * are named distinctly. {@link KnownBugGate} applies expected-failure semantics
 * against this ledger: a gated row still runs its assertion, and a fixed bug
 * fails its rows loudly until the entry (or the target) is removed.
 */
public final class KnownBugs {

    /** Classpath resource holding the committed base ledger. */
    public static final String RESOURCE = "/known-bugs.json";

    /**
     * Runtime-config key carrying the orchestrator-resolved per-repository
     * overrides: a comma-separated list of
     * {@code <language>:<majorVersion>:<repository>=<sign><id>[;<sign><id>…]}
     * entries, where {@code sign} is {@code +} (present) or {@code -} (absent),
     * e.g. {@code rust:1:aws-crypto-tools-rust=-encrypt-non-positive-frame-length-generic-error}.
     * Absent means no repository overrode its base declarations.
     */
    public static final String OVERRIDES_PROPERTY = "esdk.testserver.knownBugOverrides";
    public static final String OVERRIDES_ENV = "ESDK_TESTSERVER_KNOWN_BUG_OVERRIDES";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Set<String> ENTRY_FIELDS = Set.of("id", "description", "targets");
    private static final Set<String> TARGET_FIELDS = Set.of("language", "majorVersion", "repository");

    private static volatile KnownBugs instance;

    /** id -> entry, in ledger order. */
    private final Map<String, KnownBug> byId;

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

    /** One catalogued bug: what is wrong, and which Targets exhibit it. */
    record KnownBug(String id, String description, Set<Target> targets) {

        /** @return whether {@code target} is declared to exhibit this bug. */
        boolean exhibitedBy(Target target) {
            return targets.contains(target);
        }
    }

    private KnownBugs(Map<String, KnownBug> byId) {
        this.byId = byId;
    }

    /**
     * @return the process-wide ledger, loaded from {@value #RESOURCE} and
     *     resolved against {@value #OVERRIDES_PROPERTY} on first access.
     */
    public static KnownBugs shared() {
        KnownBugs local = instance;
        if (local == null) {
            synchronized (KnownBugs.class) {
                local = instance;
                if (local == null) {
                    local = parse(readResource(), configuredOverrides());
                    instance = local;
                }
            }
        }
        return local;
    }

    /** @return the entry for {@code id}, or empty when the ledger does not define it. */
    Optional<KnownBug> lookup(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    /** @return the ledger's bug ids, in ledger order. */
    Set<String> ids() {
        return byId.keySet();
    }

    /**
     * Parse and validate a base ledger document with no overrides applied. A
     * JSON array of entries, each with exactly the fields {@code id} (unique,
     * non-blank), {@code description} (non-blank), and {@code targets}
     * (non-empty, each a distinct {@code {language, majorVersion, repository}}
     * object). Package-private so unit tests can exercise validation without
     * the JVM-wide singleton.
     *
     * @throws IllegalArgumentException on any malformed or invalid document
     */
    static KnownBugs parse(String json) {
        return parse(json, null);
    }

    /**
     * Parse the base ledger and apply the {@code overridesRaw} overrides
     * ({@code null} or blank = none). Package-private so unit tests can exercise
     * override resolution without the JVM-wide singleton or system properties.
     *
     * @throws IllegalArgumentException on a malformed document, a malformed
     *     override, or an override that references an unknown bug id, redundantly
     *     marks a target present, or removes a target the base did not declare
     */
    static KnownBugs parse(String json, String overridesRaw) {
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (IOException e) {
            throw new IllegalArgumentException("known-bugs ledger is not valid JSON: " + e.getMessage(), e);
        }
        if (root == null || !root.isArray()) {
            throw new IllegalArgumentException(
                "known-bugs ledger root must be a JSON array of bug entries: " + RESOURCE);
        }
        Map<String, KnownBug> byId = new LinkedHashMap<>();
        for (JsonNode entry : root) {
            KnownBug bug = parseEntry(entry);
            if (byId.putIfAbsent(bug.id(), bug) != null) {
                throw new IllegalArgumentException("duplicate bug id in known-bugs ledger: " + bug.id());
            }
        }
        applyOverrides(byId, overridesRaw);
        return new KnownBugs(byId);
    }

    private static KnownBug parseEntry(JsonNode entry) {
        if (!entry.isObject()) {
            throw new IllegalArgumentException("known-bugs ledger entry must be an object: " + entry);
        }
        entry.fieldNames().forEachRemaining(field -> {
            if (!ENTRY_FIELDS.contains(field)) {
                throw new IllegalArgumentException(
                    "unknown field '" + field + "' in known-bugs ledger entry " + entry
                        + " (expected exactly " + ENTRY_FIELDS + ")");
            }
        });
        String id = requireText(entry, "id");
        String description = requireText(entry, "description");
        JsonNode targetsNode = entry.get("targets");
        if (targetsNode == null || !targetsNode.isArray() || targetsNode.isEmpty()) {
            throw new IllegalArgumentException(
                "bug '" + id + "' must declare a non-empty 'targets' array"
                    + " (a bug no target exhibits does not belong in the ledger)");
        }
        Set<Target> targets = new LinkedHashSet<>();
        for (JsonNode targetNode : targetsNode) {
            Target target = parseTarget(id, targetNode);
            if (!targets.add(target)) {
                throw new IllegalArgumentException(
                    "bug '" + id + "' declares target '" + target.label() + "' twice");
            }
        }
        return new KnownBug(id, description, targets);
    }

    private static Target parseTarget(String bugId, JsonNode targetNode) {
        if (!targetNode.isObject()) {
            throw new IllegalArgumentException(
                "bug '" + bugId + "' declares a non-object target: " + targetNode);
        }
        targetNode.fieldNames().forEachRemaining(field -> {
            if (!TARGET_FIELDS.contains(field)) {
                throw new IllegalArgumentException(
                    "unknown field '" + field + "' in a target of bug '" + bugId + "': " + targetNode
                        + " (expected exactly " + TARGET_FIELDS + ")");
            }
        });
        JsonNode majorVersionNode = targetNode.get("majorVersion");
        if (majorVersionNode == null || !majorVersionNode.canConvertToInt()) {
            throw new IllegalArgumentException(
                "a target of bug '" + bugId + "' is missing an integer 'majorVersion': " + targetNode);
        }
        try {
            return new Target(
                requireText(targetNode, "language"),
                majorVersionNode.asInt(),
                requireText(targetNode, "repository"));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "bug '" + bugId + "' declares an invalid target: " + e.getMessage(), e);
        }
    }

    /**
     * Apply {@code overridesRaw} to {@code byId} in place. Each override entry
     * names a Target and a signed list of bug ids: {@code +id} adds the Target
     * to that bug (it must not already be declared), {@code -id} removes it (it
     * must currently be declared). An override for an unknown bug id is rejected.
     */
    private static void applyOverrides(Map<String, KnownBug> byId, String overridesRaw) {
        if (overridesRaw == null || overridesRaw.isBlank()) {
            return;
        }
        for (String entry : overridesRaw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException(
                    "malformed known-bug override entry (expected "
                        + "language:major:repository=<sign><id>[;<sign><id>...]): " + trimmed);
            }
            Target target = parseOverrideTarget(trimmed.substring(0, eq).trim());
            for (String signed : trimmed.substring(eq + 1).split(";")) {
                String token = signed.trim();
                if (token.isEmpty()) {
                    continue;
                }
                applyOverrideToken(byId, target, token);
            }
        }
    }

    private static Target parseOverrideTarget(String key) {
        String[] parts = key.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException(
                "malformed known-bug override target (expected language:major:repository): " + key);
        }
        int majorVersion;
        try {
            majorVersion = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "known-bug override target major version must be an integer: " + key, e);
        }
        return new Target(parts[0].trim(), majorVersion, parts[2].trim());
    }

    private static void applyOverrideToken(Map<String, KnownBug> byId, Target target, String token) {
        char sign = token.charAt(0);
        if (sign != '+' && sign != '-') {
            throw new IllegalArgumentException(
                "known-bug override for '" + target.label() + "' must sign each id with '+' "
                    + "(present) or '-' (absent): " + token);
        }
        String bugId = token.substring(1).trim();
        if (bugId.isEmpty()) {
            throw new IllegalArgumentException(
                "known-bug override for '" + target.label() + "' has an empty bug id: " + token);
        }
        KnownBug bug = byId.get(bugId);
        if (bug == null) {
            throw new IllegalArgumentException(
                "known-bug override for '" + target.label() + "' references unknown bug id '"
                    + bugId + "'; the base ledger defines " + byId.keySet());
        }
        Set<Target> targets = new LinkedHashSet<>(bug.targets());
        if (sign == '+') {
            if (!targets.add(target)) {
                throw new IllegalArgumentException(
                    "redundant known-bug override: '" + target.label() + "' already declares '"
                        + bugId + "' in the base ledger");
            }
        } else if (!targets.remove(target)) {
            throw new IllegalArgumentException(
                "stale known-bug override: '" + target.label() + "' marks '" + bugId
                    + "' absent, but the base ledger does not declare it for that target");
        }
        byId.put(bugId, new KnownBug(bug.id(), bug.description(), targets));
    }

    private static String requireText(JsonNode entry, String field) {
        JsonNode value = entry.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw new IllegalArgumentException(
                "known-bugs ledger entry is missing a non-blank '" + field + "': " + entry);
        }
        return value.asText();
    }

    private static String configuredOverrides() {
        String fromProperty = System.getProperty(OVERRIDES_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return System.getenv(OVERRIDES_ENV);
    }

    private static String readResource() {
        try (InputStream in = KnownBugs.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(
                    "known-bugs ledger resource " + RESOURCE + " is missing from the test classpath");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("failed reading known-bugs ledger resource " + RESOURCE, e);
        }
    }
}
