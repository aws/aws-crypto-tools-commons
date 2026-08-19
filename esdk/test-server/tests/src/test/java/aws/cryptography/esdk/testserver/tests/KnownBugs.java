package aws.cryptography.esdk.testserver.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The known-bug ledger: catalogued, reproduced BUGS in the ESDK implementations
 * under test — wrong behavior a Test correctly fails, not missing capability (a
 * missing capability is a Feature_Declaration concern, {@link FeatureDeclarations}).
 *
 * <p>The committed <em>base</em> ledger, loaded from {@value #RESOURCE} in this
 * module, is authoritative: it lists every bug and the {@link Target}s
 * exhibiting it. A Language_Repository cannot add bugs here — it can only
 * declare its own <em>fixes</em>. Its commons-configuration file's
 * {@code knownBugs} array names base-ledger bug ids that repository's target has
 * fixed; the orchestrator resolves those per target and hands the Tests
 * {@value #FIXES_PROPERTY} (mirroring {@code esdk.testserver.features}).
 * Applying a fix simply removes that target from the bug — <em>idempotently</em>:
 * a fix for a bug the base does not attribute to the target (or no longer
 * defines at all) is a silent no-op, never an error. That makes reconciling a
 * merged fix into this base ledger order-independent — commons can drop the
 * target whenever, and the repository's now-satisfied {@code knownBugs} entry
 * keeps working as a no-op until it too is cleaned up.
 *
 * <p>Each entry carries a stable {@code id}, a one-line {@code description}, and
 * the {@link Target}s — {@code (language, majorVersion, repository)} triples,
 * not bare languages — exhibiting it. {@link KnownBugGate} applies
 * expected-failure semantics against the resolved ledger: a gated row still runs
 * its assertion, and a fixed bug fails its rows loudly until the base entry (or
 * the target) is removed.
 */
public final class KnownBugs {

    /** Classpath resource holding the committed base ledger. */
    public static final String RESOURCE = "/known-bugs.json";

    /**
     * Runtime-config key carrying the orchestrator-resolved per-repository bug
     * FIXES: a comma-separated list of
     * {@code <language>:<majorVersion>:<repository>=<id>[;<id>…]} entries, e.g.
     * {@code rust:1:aws-crypto-tools-rust=encrypt-non-positive-frame-length-generic-error}.
     * Each id is a base-ledger bug the target has fixed; applying it removes that
     * target from the bug. Absent means no repository declared a fix.
     */
    public static final String FIXES_PROPERTY = "esdk.testserver.knownBugFixes";
    public static final String FIXES_ENV = "ESDK_TESTSERVER_KNOWN_BUG_FIXES";

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
     *     resolved against {@value #FIXES_PROPERTY} on first access.
     */
    public static KnownBugs shared() {
        KnownBugs local = instance;
        if (local == null) {
            synchronized (KnownBugs.class) {
                local = instance;
                if (local == null) {
                    local = parse(readResource(), configuredFixes());
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
     * Parse and validate a base ledger document with no fixes applied. A JSON
     * array of entries, each with exactly the fields {@code id} (unique,
     * non-blank), {@code description} (non-blank), and {@code targets}
     * (non-empty, each a distinct {@code {language, majorVersion, repository}}
     * object). Package-private so unit tests can exercise validation without the
     * JVM-wide singleton.
     *
     * @throws IllegalArgumentException on any malformed or invalid document
     */
    static KnownBugs parse(String json) {
        return parse(json, null);
    }

    /**
     * Parse the base ledger and apply the {@code fixesRaw} fixes ({@code null}
     * or blank = none). Package-private so unit tests can exercise fix
     * resolution without the JVM-wide singleton or system properties.
     *
     * <p>Fix application is idempotent and never throws: a fix for an unknown
     * bug id, or for a target the base does not attribute the bug to, is a
     * silent no-op.
     *
     * @throws IllegalArgumentException only on a malformed base ledger document
     */
    static KnownBugs parse(String json, String fixesRaw) {
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
        applyFixes(byId, fixesRaw);
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
     * Apply {@code fixesRaw} to {@code byId} in place: for each
     * {@code language:major:repository=id[;id…]} entry, remove that Target from
     * each named bug. Idempotent and total — an unknown bug id, or a target the
     * base does not attribute the bug to, is a silent no-op; a malformed entry
     * is skipped. The property is orchestrator-generated from validated
     * configuration, so leniency here only guarantees a resolved fix can never
     * fail a run.
     */
    private static void applyFixes(Map<String, KnownBug> byId, String fixesRaw) {
        if (fixesRaw == null || fixesRaw.isBlank()) {
            return;
        }
        for (String entry : fixesRaw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                continue;
            }
            Target target = parseFixTarget(trimmed.substring(0, eq).trim());
            if (target == null) {
                continue;
            }
            for (String idToken : trimmed.substring(eq + 1).split(";")) {
                String bugId = idToken.trim();
                if (bugId.isEmpty()) {
                    continue;
                }
                KnownBug bug = byId.get(bugId);
                if (bug == null || !bug.targets().contains(target)) {
                    continue;
                }
                Set<Target> targets = new LinkedHashSet<>(bug.targets());
                targets.remove(target);
                byId.put(bugId, new KnownBug(bug.id(), bug.description(), targets));
            }
        }
    }

    /** Parse a {@code language:major:repository} fix key, or {@code null} if malformed. */
    private static Target parseFixTarget(String key) {
        String[] parts = key.split(":");
        if (parts.length != 3) {
            return null;
        }
        int majorVersion;
        try {
            majorVersion = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            return null;
        }
        try {
            return new Target(parts[0].trim(), majorVersion, parts[2].trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String requireText(JsonNode entry, String field) {
        JsonNode value = entry.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw new IllegalArgumentException(
                "known-bugs ledger entry is missing a non-blank '" + field + "': " + entry);
        }
        return value.asText();
    }

    private static String configuredFixes() {
        String fromProperty = System.getProperty(FIXES_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return System.getenv(FIXES_ENV);
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
