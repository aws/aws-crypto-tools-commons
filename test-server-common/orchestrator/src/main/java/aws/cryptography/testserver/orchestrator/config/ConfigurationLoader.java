package aws.cryptography.testserver.orchestrator.config;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads the TestServer's three-file configuration. The commons configuration is
 * the trio {@code server-config.json} (product + entries), {@code feature-set.json}
 * (the Feature_Catalog) and {@code bug-list.json} (the bug ledger); a
 * Language_Repository declares itself with the sibling trio
 * {@code server-config.json} + {@code feature-config.json} + {@code bug-config.json}.
 * It is the only supported format.
 *
 * <p><b>Strict duplicate detection.</b> The shared mapper enables Jackson's
 * {@code STRICT_DUPLICATE_DETECTION}, so a duplicate JSON key anywhere in either
 * file kind is an unparseable-file error, never a silent last-value-wins.
 *
 * <p><b>Lenient fields, strict structure.</b> A missing field parses as
 * {@code null} (an absent object as a {@code null} object) so that validation —
 * not the parser — is the single place that rejects an under-specified entry and
 * names the language and each missing element. Structural problems (missing
 * file, malformed JSON, duplicate key, non-object top level) raise a
 * {@link ConfigurationLoadException} whose message names the expected location.
 */
public final class ConfigurationLoader {

    private static final ObjectMapper MAPPER = JsonMapper.builder()
        // Duplicate JSON keys are validation errors everywhere; unparseable-file
        // handling depends on it.
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .build();

    private ConfigurationLoader() {
    }

    // ------------------------------------------------------------------
    // commons configuration
    // ------------------------------------------------------------------

    /**
     * Load and parse (without validating) the commons configuration rooted at
     * {@code path} — a config directory or its {@code server-config.json}. The
     * three files are {@code server-config.json} (product + entries [+ optional
     * requiredKmsScenarios]), {@code feature-set.json} (the Feature_Catalog) and
     * {@code bug-list.json} (the bug ledger). Absence of {@code server-config.json}
     * is a {@link ConfigurationLoadException} naming the expected location.
     */
    public static CommonsConfiguration loadCommonsConfiguration(Path path) {
        Path dir = Files.isDirectory(path) ? path : path.getParent();
        Path serverConfig = dir == null ? path : dir.resolve("server-config.json");
        if (dir == null || !Files.isRegularFile(serverConfig)) {
            throw new ConfigurationLoadException(
                "commons configuration file not found at the expected location: " + serverConfig
                    + " — the TestServer requires the three-file configuration"
                    + " (server-config.json + feature-set.json + bug-list.json)",
                serverConfig);
        }
        return loadCommonsConfigurationTrio(dir);
    }

    /**
     * Assemble a {@link CommonsConfiguration} from the split commons trio in
     * {@code dir}: {@code server-config.json} ({@code product} + {@code entries}
     * [+ optional {@code requiredKmsScenarios}]) and {@code feature-set.json}
     * ({@code features} — the Feature_Catalog), plus the optional
     * {@code bug-list.json} bug ledger.
     */
    private static CommonsConfiguration loadCommonsConfigurationTrio(Path dir) {
        Path serverPath = dir.resolve("server-config.json");
        Path featurePath = dir.resolve("feature-set.json");
        JsonNode server = readObject(
            "server-config.json", read("server-config.json", serverPath), serverPath);
        JsonNode feature = readObject(
            "feature-set.json", read("feature-set.json", featurePath), featurePath);
        // Validate the bug ledger (design "Bug Configuration") when present: a
        // 'bugs' object keyed by bug id, each { description, ticketId? } with a
        // non-blank description. Structural validation only — validating here
        // fails a malformed ledger fast, at load, before anything is cloned.
        Path bugPath = dir.resolve("bug-list.json");
        List<String> bugLedgerIds = List.of();
        if (Files.isRegularFile(bugPath)) {
            bugLedgerIds = validateBugLedger(readObject("bug-list.json", read("bug-list.json", bugPath), bugPath), bugPath);
        }
        List<ConfigurationEntry> entries = new ArrayList<>();
        JsonNode entriesNode = server.get("entries");
        if (entriesNode != null && entriesNode.isArray()) {
            for (JsonNode n : entriesNode) {
                entries.add(parseEntry(n));
            }
        }
        return new CommonsConfiguration(
            text(server, "product"),
            stringList(feature.get("features")),
            entries,
            server.get("requiredKmsScenarios") == null
                ? null : stringList(server.get("requiredKmsScenarios")),
            bugLedgerIds);
    }

    // ------------------------------------------------------------------
    // Commons-configuration file (Language_Repository)
    // ------------------------------------------------------------------

    /**
     * Load and parse (without validating) a Language_Repository's per-server
     * configuration rooted at {@code path} — a directory or its
     * {@code server-config.json}. The trio is {@code server-config.json}
     * ({@code commonsRepository}, {@code product} [+ optional
     * {@code configurationOverrides}]), {@code feature-config.json} (the
     * Feature_Declaration) and {@code bug-config.json} (the exhibited-bug list).
     * Absence of {@code server-config.json} is a {@link ConfigurationLoadException}
     * naming the expected location.
     */
    public static ServerConfiguration loadServerConfiguration(Path path) {
        Path dir = Files.isDirectory(path) ? path : path.getParent();
        Path serverConfig = dir == null ? path : dir.resolve("server-config.json");
        if (dir == null || !Files.isRegularFile(serverConfig)) {
            throw new ConfigurationLoadException(
                "per-server configuration file not found at the expected location: "
                    + serverConfig + " — the TestServer requires the three-file configuration"
                    + " (server-config.json + feature-config.json + bug-config.json)",
                serverConfig);
        }
        return loadServerConfigurationTrio(dir);
    }

    /**
     * Assemble a {@link ServerConfiguration} from a Language_Repository's split
     * trio in {@code dir}: {@code server-config.json} ({@code commonsRepository},
     * {@code product} [+ optional {@code configurationOverrides}]) and
     * {@code feature-config.json} (the {@code supportedFeatures} /
     * {@code unsupportedFeatures} Feature_Declaration [+ optional
     * {@code rawRsaPaddingSchemes}]), plus the optional {@code bug-config.json}
     * exhibited-bug list.
     */
    private static ServerConfiguration loadServerConfigurationTrio(Path dir) {
        Path serverPath = dir.resolve("server-config.json");
        Path featurePath = dir.resolve("feature-config.json");
        JsonNode server = readObject(
            "server-config.json", read("server-config.json", serverPath), serverPath);
        JsonNode feature = readObject(
            "feature-config.json", read("feature-config.json", featurePath), featurePath);
        // Validate this server's exhibited-bug list (design "Bug Configuration")
        // when present: a JSON array of non-blank, unique bug-id strings. The
        // cross-check that each id is defined in the commons ledger runs where
        // both are in hand (with the known-bug injection); here we fail a
        // malformed list fast, at load.
        Path bugPath = dir.resolve("bug-config.json");
        List<String> bugIds = List.of();
        if (Files.isRegularFile(bugPath)) {
            bugIds = validatePerServerBugIds(read("bug-config.json", bugPath), bugPath);
        }
        List<ConfigurationEntry> overrides = null;
        JsonNode overridesNode = server.get("configurationOverrides");
        if (overridesNode != null && overridesNode.isArray()) {
            overrides = new ArrayList<>();
            for (JsonNode n : overridesNode) {
                overrides.add(parseEntry(n));
            }
        }
        return new ServerConfiguration(
            coordinates(server.get("commonsRepository")),
            text(server, "product"),
            stringList(feature.get("supportedFeatures")),
            stringList(feature.get("unsupportedFeatures")),
            stringList(feature.get("rawRsaPaddingSchemes")),
            overrides,
            bugIds);
    }

    // ------------------------------------------------------------------
    // Shared pieces
    // ------------------------------------------------------------------

    /** Parse one Configuration_Entry (also the shape of a Configuration_Override). */
    private static ConfigurationEntry parseEntry(JsonNode n) {
        return new ConfigurationEntry(
            text(n, "language"),
            integer(n, "majorVersion"),
            integer(n, "port"),
            coordinates(n.get("libraryRepository")),
            serverLocation(n.get("serverLocation")),
            stringList(n.get("supportedFeatures")),
            stringList(n.get("unsupportedFeatures")),
            stringList(n.get("rawRsaPaddingSchemes")),
            text(n, "configPath"));
    }

    private static RepositoryCoordinates coordinates(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        String path = text(node, "path");
        return new RepositoryCoordinates(
            text(node, "name"),
            text(node, "url"),
            text(node, "branch"),
            path == null ? RepositoryCoordinates.DEFAULT_PATH : path);
    }

    private static ServerLocation serverLocation(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        return new ServerLocation(
            text(node, "repository"),
            text(node, "url"),
            text(node, "ref"),
            text(node, "path"));
    }

    private static String read(String kind, Path path) {
        if (!Files.isRegularFile(path)) {
            throw new ConfigurationLoadException(
                kind + " file not found at the expected location: " + path, path);
        }
        try {
            return Files.readString(path);
        } catch (IOException e) {
            throw new ConfigurationLoadException(
                kind + " file at " + path + " could not be read: " + e.getMessage(), path, e);
        }
    }

    /** Parse {@code json} into a top-level JSON object, or throw naming the location. */
    private static JsonNode readObject(String kind, String json, Path location) {
        String where = location == null ? "" : " at " + location;
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (JacksonException e) {
            throw new ConfigurationLoadException(
                kind + " file" + where + " is unparseable: " + e.getOriginalMessage(), location, e);
        }
        if (root == null || !root.isObject()) {
            throw new ConfigurationLoadException(
                kind + " file" + where + " is unparseable: expected a top-level JSON object",
                location);
        }
        return root;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }

    /**
     * Validate a commons bug ledger (design "Bug Configuration"): a {@code bugs}
     * array of {@code { id, description, ticketId? }} with unique, non-blank ids
     * and non-blank descriptions. Structural validation at load, before
     * anything is cloned; throws {@link ConfigurationLoadException} naming the
     * file on any violation.
     *
     * @return the ledger's bug ids, in ledger order.
     */
    private static List<String> validateBugLedger(JsonNode root, Path location) {
        JsonNode bugs = root.get("bugs");
        if (bugs == null || !bugs.isObject()) {
            throw new ConfigurationLoadException(
                "bug-list.json at " + location + " must have a 'bugs' object keyed by bug id", location);
        }
        List<String> ids = new ArrayList<>();
        java.util.Iterator<String> names = bugs.fieldNames();
        while (names.hasNext()) {
            String id = names.next();
            if (id == null || id.isBlank()) {
                throw new ConfigurationLoadException(
                    "bug-list.json at " + location + ": each bug id (object key) must be non-blank", location);
            }
            JsonNode bug = bugs.get(id);
            if (bug == null || !bug.isObject()) {
                throw new ConfigurationLoadException(
                    "bug-list.json at " + location + ": bug '" + id + "' must map to an object", location);
            }
            String description = text(bug, "description");
            if (description == null || description.isBlank()) {
                throw new ConfigurationLoadException(
                    "bug-list.json at " + location + ": bug '" + id
                        + "' needs a non-blank 'description'", location);
            }
            ids.add(id);
        }
        return List.copyOf(ids);
    }

    /**
     * Validate a per-server exhibited-bug list (design "Bug Configuration"): a
     * JSON array of non-blank, unique id strings. Throws
     * {@link ConfigurationLoadException} on any violation.
     *
     * @return the exhibited bug ids, in file order.
     */
    private static List<String> validatePerServerBugIds(String json, Path location) {
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (JacksonException e) {
            throw new ConfigurationLoadException(
                "bug-config.json at " + location + " is unparseable: " + e.getOriginalMessage(),
                location, e);
        }
        if (root == null || !root.isArray()) {
            throw new ConfigurationLoadException(
                "bug-config.json at " + location + " must be a JSON array of bug ids", location);
        }
        java.util.Set<String> ids = new java.util.LinkedHashSet<>();
        for (JsonNode idNode : root) {
            if (!idNode.isTextual() || idNode.asText().isBlank()) {
                throw new ConfigurationLoadException(
                    "bug-config.json at " + location + ": each bug id must be a non-blank string",
                    location);
            }
            if (!ids.add(idNode.asText())) {
                throw new ConfigurationLoadException(
                    "bug-config.json at " + location + ": duplicate bug id '" + idNode.asText() + "'",
                    location);
            }
        }
        return List.copyOf(new ArrayList<>(ids));
    }

    private static Integer integer(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        // Preserve non-integer JSON as null so validation reports "missing"
        // rather than silently coercing.
        return v.canConvertToInt() ? v.asInt() : null;
    }

    /**
     * Parse a JSON array of strings, preserving duplicates so the duplicate-name
     * checks can see them. Absent or non-array values parse as {@code null} ("no
     * such array"), for validation to reject.
     */
    private static List<String> stringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return null;
        }
        List<String> values = new ArrayList<>();
        for (JsonNode v : node) {
            values.add(v.isNull() ? null : v.asText());
        }
        return values;
    }
}
