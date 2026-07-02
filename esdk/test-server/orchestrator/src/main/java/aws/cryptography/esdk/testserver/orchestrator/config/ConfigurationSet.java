package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The collection of {@link ConfigurationEntry}, one per {@code Language_Server}
 * (Requirement 9.1), with the cross-entry uniqueness invariant on {@code port}
 * (Requirement 9.3).
 *
 * <p>{@link #validate()} is a pure function over the entries (design Testing
 * Strategy — Property 11 runs against this in-process unit without launching any
 * server). It rejects a set whose any entry omits its branch, repository, major
 * version, or port, specifies a major version below 1 or a port outside 1..65535,
 * or whose two entries share a port; every rejection identifies the offending
 * entry and the set itself is never mutated (Requirement 9.5).
 */
public final class ConfigurationSet {

    /** Lowest and highest legal TCP port (Requirement 9.2). */
    public static final int MIN_PORT = 1;
    public static final int MAX_PORT = 65535;

    private final List<ConfigurationEntry> entries;

    public ConfigurationSet(List<ConfigurationEntry> entries) {
        this.entries = List.copyOf(entries);
    }

    public List<ConfigurationEntry> entries() {
        return entries;
    }

    /** @return the entry for {@code language}, or {@code null} if absent. */
    public ConfigurationEntry forLanguage(String language) {
        for (ConfigurationEntry e : entries) {
            if (language.equals(e.language())) {
                return e;
            }
        }
        return null;
    }

    /**
     * Validate the set without mutating it (Requirement 9.5, Property 11).
     *
     * @return a {@link ConfigurationSetValidation}; {@code valid()} is
     *     {@code false} with one message per problem when any entry is malformed
     *     or two entries share a port.
     */
    public ConfigurationSetValidation validate() {
        List<String> errors = new ArrayList<>();

        // Per-entry field validation (Requirement 9.2).
        for (ConfigurationEntry e : entries) {
            String id = e.identity();
            if (e.language() == null || e.language().isBlank()) {
                errors.add("entry " + id + ": missing language");
            }
            if (e.branch() == null || e.branch().isBlank()) {
                errors.add("entry " + id + ": missing branch");
            }
            if (e.repository() == null || e.repository().isBlank()) {
                errors.add("entry " + id + ": missing repository");
            }
            if (e.majorVersion() == null) {
                errors.add("entry " + id + ": missing majorVersion");
            } else if (e.majorVersion() < 1) {
                errors.add("entry " + id + ": majorVersion " + e.majorVersion() + " must be >= 1");
            }
            if (e.port() == null) {
                errors.add("entry " + id + ": missing port");
            } else if (e.port() < MIN_PORT || e.port() > MAX_PORT) {
                errors.add("entry " + id + ": port " + e.port()
                    + " out of range " + MIN_PORT + ".." + MAX_PORT);
            }
        }

        // Cross-entry port uniqueness (Requirement 9.3). Only well-formed ports
        // participate; a missing/out-of-range port is already reported above.
        Map<Integer, String> portOwner = new HashMap<>();
        Set<String> reportedDup = new HashSet<>();
        for (ConfigurationEntry e : entries) {
            Integer port = e.port();
            if (port == null || port < MIN_PORT || port > MAX_PORT) {
                continue;
            }
            String prior = portOwner.putIfAbsent(port, e.identity());
            if (prior != null) {
                String key = port + "|" + prior + "|" + e.identity();
                if (reportedDup.add(key)) {
                    errors.add("entries " + prior + " and " + e.identity()
                        + " share port " + port);
                }
            }
        }

        return new ConfigurationSetValidation(errors.isEmpty(), errors);
    }
}
