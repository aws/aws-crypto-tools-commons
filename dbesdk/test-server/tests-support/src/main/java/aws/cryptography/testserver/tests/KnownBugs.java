package aws.cryptography.testserver.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The known-bug ledger: catalogued, reproduced BUGS in the Language_Server
 * implementations under test — wrong behavior a Test correctly fails, not
 * missing capability (a missing capability is a Feature_Declaration concern,
 * {@link FeatureDeclarations}). Loaded once per JVM from {@value #RESOURCE} on
 * the consuming Tests suite's classpath: the suite observed the findings, so
 * the suite owns the ledger — language repositories declare nothing here.
 *
 * <p>Each entry carries a stable {@code id}, a one-line {@code description} of
 * the wrong behavior, and the {@code languages} exhibiting it. Entries are
 * narrow — one manifestation per entry (per operation, and per suite variant
 * where the bug is variant-specific) — so an entry never covers a row that is
 * not a genuine manifestation. {@link KnownBugGate} applies expected-failure
 * semantics against this ledger: a gated row still runs its assertion, and a
 * fixed bug fails its rows loudly until the entry is removed.
 */
public final class KnownBugs {

    /** Classpath resource holding the ledger. */
    public static final String RESOURCE = "/known-bugs.json";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Set<String> ENTRY_FIELDS = Set.of("id", "description", "languages");

    private static volatile KnownBugs instance;

    /** id -> entry, in ledger order. */
    private final Map<String, KnownBug> byId;

    /** One catalogued bug: what is wrong, and which languages exhibit it. */
    record KnownBug(String id, String description, List<String> languages) {

        /** @return whether {@code language} is declared to exhibit this bug. */
        boolean exhibitedBy(String language) {
            return languages.contains(language);
        }
    }

    private KnownBugs(Map<String, KnownBug> byId) {
        this.byId = byId;
    }

    /** @return the process-wide ledger, loaded from {@value #RESOURCE} on first access. */
    public static KnownBugs shared() {
        KnownBugs local = instance;
        if (local == null) {
            synchronized (KnownBugs.class) {
                local = instance;
                if (local == null) {
                    local = parse(readResource());
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
     * Parse and validate a ledger document: a JSON array of entries, each with
     * exactly the fields {@code id} (unique, non-blank), {@code description}
     * (non-blank), and {@code languages} (non-empty, non-blank, no duplicates).
     * Package-private so unit tests can exercise validation without the
     * JVM-wide singleton.
     *
     * @throws IllegalArgumentException on any malformed or invalid document
     */
    static KnownBugs parse(String json) {
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
        JsonNode languagesNode = entry.get("languages");
        if (languagesNode == null || !languagesNode.isArray() || languagesNode.isEmpty()) {
            throw new IllegalArgumentException(
                "bug '" + id + "' must declare a non-empty 'languages' array"
                    + " (a bug no language exhibits does not belong in the ledger)");
        }
        Set<String> languages = new LinkedHashSet<>();
        for (JsonNode languageNode : languagesNode) {
            if (!languageNode.isTextual() || languageNode.asText().isBlank()) {
                throw new IllegalArgumentException(
                    "bug '" + id + "' declares a non-text or blank language: " + languageNode);
            }
            if (!languages.add(languageNode.asText())) {
                throw new IllegalArgumentException(
                    "bug '" + id + "' declares language '" + languageNode.asText() + "' twice");
            }
        }
        return new KnownBug(id, description, List.copyOf(new ArrayList<>(languages)));
    }

    private static String requireText(JsonNode entry, String field) {
        JsonNode value = entry.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw new IllegalArgumentException(
                "known-bugs ledger entry is missing a non-blank '" + field + "': " + entry);
        }
        return value.asText();
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
