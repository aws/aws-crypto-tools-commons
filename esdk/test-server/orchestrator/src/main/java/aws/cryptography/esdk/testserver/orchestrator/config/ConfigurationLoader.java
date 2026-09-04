package aws.cryptography.esdk.testserver.orchestrator.config;

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
 * Loads the two configuration file kinds of the TestServer: the commons
 * {@code Configuration_Set} ({@code server-config.json}) and a
 * Language_Repository's commons-configuration file.
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
    // Configuration_Set
    // ------------------------------------------------------------------

    /**
     * Load and parse (without validating) the Configuration_Set from a config
     * directory holding {@code server-config.json} (product + entries) and
     * {@code feature-config.json} (the Feature_Catalog), the two living side by
     * side. Combined into one {@link ConfigurationSet}.
     */
    public static ConfigurationSet loadConfigurationSet(Path configDir) {
        Path serverFile = configDir.resolve("server-config.json");
        Path featureFile = configDir.resolve("feature-config.json");
        Path bugFile = configDir.resolve("bug-config.json");
        JsonNode server = readObject("server-config", read("server-config", serverFile), serverFile);
        JsonNode feature = readObject("feature-config", read("feature-config", featureFile), featureFile);
        JsonNode bug = readObject("bug-config", read("bug-config", bugFile), bugFile);
        List<ConfigurationEntry> entries = new ArrayList<>();
        JsonNode entriesNode = server.get("entries");
        if (entriesNode != null && entriesNode.isArray()) {
            for (JsonNode n : entriesNode) {
                entries.add(parseEntry(n));
            }
        }
        List<BugLedgerEntry> ledger = new ArrayList<>();
        JsonNode bugsNode = bug.get("bugs");
        if (bugsNode != null && bugsNode.isArray()) {
            for (JsonNode n : bugsNode) {
                ledger.add(new BugLedgerEntry(
                    text(n, "id"), text(n, "description"), text(n, "ticketId")));
            }
        }
        return new ConfigurationSet(
            text(server, "product"),
            stringList(feature.get("features")),
            entries,
            ledger);
    }

    /** Parse (without validating) a Configuration_Set from a JSON string. */
    public static ConfigurationSet parseConfigurationSet(String json) {
        return parseConfigurationSet(json, null);
    }

    private static ConfigurationSet parseConfigurationSet(String json, Path location) {
        JsonNode root = readObject("Configuration_Set", json, location);
        List<ConfigurationEntry> entries = new ArrayList<>();
        JsonNode entriesNode = root.get("entries");
        if (entriesNode != null && entriesNode.isArray()) {
            for (JsonNode n : entriesNode) {
                entries.add(parseEntry(n));
            }
        }
        return new ConfigurationSet(
            text(root, "product"),
            stringList(root.get("features")),
            entries);
    }

    // ------------------------------------------------------------------
    // Commons-configuration file (Language_Repository)
    // ------------------------------------------------------------------

    /**
     * Load and parse (without validating) a Language_Server's config from its
     * directory, combining {@code server-config.json} (Commons_Configuration_Entry
     * + product + any configurationOverrides) and {@code feature-config.json}
     * (the Feature_Declaration) — the two living side by side next to the
     * server's {@code bug-config.json} — into one {@link CommonsConfiguration}.
     */
    public static CommonsConfiguration loadCommonsConfiguration(Path serverDir) {
        Path serverFile = serverDir.resolve("server-config.json");
        Path featureFile = serverDir.resolve("feature-config.json");
        JsonNode server = readObject("server-config", read("server-config", serverFile), serverFile);
        JsonNode feature = readObject("feature-config", read("feature-config", featureFile), featureFile);
        List<ConfigurationEntry> overrides = null;
        JsonNode overridesNode = server.get("configurationOverrides");
        if (overridesNode != null && overridesNode.isArray()) {
            overrides = new ArrayList<>();
            for (JsonNode n : overridesNode) {
                overrides.add(parseEntry(n));
            }
        }
        return new CommonsConfiguration(
            coordinates(server.get("commonsRepository")),
            text(server, "product"),
            stringList(feature.get("supportedFeatures")),
            stringList(feature.get("unsupportedFeatures")),
            stringList(feature.get("rawRsaPaddingSchemes")),
            overrides);
    }

    /** Parse (without validating) a commons-configuration file from a JSON string. */
    public static CommonsConfiguration parseCommonsConfiguration(String json) {
        return parseCommonsConfiguration(json, null);
    }

    private static CommonsConfiguration parseCommonsConfiguration(String json, Path location) {
        JsonNode root = readObject("commons-configuration", json, location);
        List<ConfigurationEntry> overrides = null;
        JsonNode overridesNode = root.get("configurationOverrides");
        if (overridesNode != null && overridesNode.isArray()) {
            overrides = new ArrayList<>();
            for (JsonNode n : overridesNode) {
                overrides.add(parseEntry(n));
            }
        }
        return new CommonsConfiguration(
            coordinates(root.get("commonsRepository")),
            text(root, "product"),
            stringList(root.get("supportedFeatures")),
            stringList(root.get("unsupportedFeatures")),
            stringList(root.get("rawRsaPaddingSchemes")),
            overrides);
    }

    // ------------------------------------------------------------------
    // Bug-configuration file (Language_Server)
    // ------------------------------------------------------------------

    /**
     * Load a Language_Server's {@code bug-config.json}: a flat JSON array
     * of the bug ids that server currently exhibits (design "Bug Configuration").
     * A <b>missing</b> file means the server declares no bug (empty list) — a
     * server with zero bugs need not ship the file. A present-but-unparseable
     * file, or a non-array top level, is a {@link ConfigurationLoadException}
     * naming the location.
     */
    public static List<String> loadBugConfiguration(Path path) {
        if (!Files.isRegularFile(path)) {
            return List.of();
        }
        String json;
        try {
            json = Files.readString(path);
        } catch (IOException e) {
            throw new ConfigurationLoadException(
                "bug-configuration file at " + path + " could not be read: " + e.getMessage(),
                path, e);
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (JacksonException e) {
            throw new ConfigurationLoadException(
                "bug-configuration file at " + path + " is unparseable: " + e.getOriginalMessage(),
                path, e);
        }
        if (root == null || !root.isArray()) {
            throw new ConfigurationLoadException(
                "bug-configuration file at " + path
                    + " is unparseable: expected a top-level JSON array of bug id strings",
                path);
        }
        List<String> ids = new ArrayList<>();
        for (JsonNode v : root) {
            ids.add(v.isNull() ? null : v.asText());
        }
        return ids;
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
            text(n, "configPath"),
            stringList(n.get("knownBugs")));
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
