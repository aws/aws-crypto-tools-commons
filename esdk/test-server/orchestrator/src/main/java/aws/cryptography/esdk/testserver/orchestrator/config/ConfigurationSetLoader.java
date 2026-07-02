package aws.cryptography.esdk.testserver.orchestrator.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads the declarative {@link ConfigurationSet} from the
 * {@code configuration-set.json} file in the commons repo (Requirement 9.1).
 *
 * <p>Parsing is intentionally lenient: a missing field is read as {@code null}
 * rather than a parse error, so that {@link ConfigurationSet#validate()} — not
 * the parser — is the single place that rejects malformed entries and identifies
 * the offending entry (Requirement 9.5). Only structurally-invalid JSON (not a
 * JSON object with an {@code entries} array) is rejected here.
 */
public final class ConfigurationSetLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ConfigurationSetLoader() {
    }

    /** Load and parse (without validating) the configuration set at {@code path}. */
    public static ConfigurationSet load(Path path) {
        try {
            String json = Files.readString(path);
            return parse(json);
        } catch (IOException e) {
            throw new UncheckedIOException("could not read configuration set at " + path, e);
        }
    }

    /** Parse (without validating) a configuration set from a JSON string. */
    public static ConfigurationSet parse(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode entriesNode = root.get("entries");
            if (entriesNode == null || !entriesNode.isArray()) {
                throw new IllegalArgumentException(
                    "configuration set must be a JSON object with an \"entries\" array");
            }
            List<ConfigurationEntry> entries = new ArrayList<>();
            for (JsonNode n : entriesNode) {
                entries.add(new ConfigurationEntry(
                    text(n, "language"),
                    text(n, "branch"),
                    text(n, "repository"),
                    integer(n, "majorVersion"),
                    integer(n, "port")
                ));
            }
            return new ConfigurationSet(entries);
        } catch (IOException e) {
            throw new UncheckedIOException("could not parse configuration set JSON", e);
        }
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
        return v.isInt() || v.isLong() ? v.asInt() : (v.canConvertToInt() ? v.asInt() : null);
    }
}
