package aws.cryptography.testserver.orchestrator.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The {@code errors} block of a server's {@code feature-config.json}.
 * It says which parts of an error the shared tests check for this server.
 *
 * <pre>{@code
 * "errors": {
 *   "supported":   { "kind": { "version": 2 }, "service": { "version": 1 } },
 *   "unsupported": { "message": "Rust messages can change in any release" }
 * }
 * }</pre>
 *
 * <p>A check in {@code supported} runs at that version.
 * A check in {@code unsupported} is off, and the reason says why.
 * A check in neither list is off too, because nobody has decided yet.
 *
 * @param supported   check name to version, in file order
 * @param unsupported check name to the reason it is off, in file order
 */
public record ErrorChecks(Map<String, Integer> supported, Map<String, String> unsupported) {

    /** Every check the shared tests know. A server config may name only these. */
    public static final List<String> CHECKS = List.of(
        "kind", "service", "resource", "code",
        "retryable", "retryKind", "conflictReason", "message");

    /** The value {@link #flatten()} gives a check in {@code unsupported}. */
    public static final String UNSUPPORTED = "unsupported";

    public ErrorChecks {
        supported = Collections.unmodifiableMap(new LinkedHashMap<>(supported));
        unsupported = Collections.unmodifiableMap(new LinkedHashMap<>(unsupported));
    }

    /**
     * Each declared check as one string for the test JVM:
     * the version number, or {@link #UNSUPPORTED}.
     */
    public Map<String, String> flatten() {
        Map<String, String> flat = new LinkedHashMap<>();
        supported.forEach((check, version) -> flat.put(check, Integer.toString(version)));
        unsupported.keySet().forEach(check -> flat.put(check, UNSUPPORTED));
        return flat;
    }
}
