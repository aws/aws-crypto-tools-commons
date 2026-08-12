package aws.cryptography.mpl.testserver.tests;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Resolves Language_Server targets from {@code mpl.testserver.targets}.
 * Format: {@code rust:1=http://127.0.0.1:8093,...}
 */
public final class LanguageServerRegistry {

    public record Target(String language, int majorVersion, URI endpoint) {
    }

    public record EndpointPair(Target server1, Target server2) {
    }

    private static final LanguageServerRegistry INSTANCE = new LanguageServerRegistry();

    private final List<Target> targets;

    private LanguageServerRegistry() {
        String prop = System.getProperty("mpl.testserver.targets", "");
        targets = new ArrayList<>();
        if (!prop.isBlank()) {
            for (String entry : prop.split(",")) {
                String[] parts = entry.split("=", 2);
                String[] langVer = parts[0].split(":", 2);
                targets.add(new Target(
                    langVer[0].trim(),
                    Integer.parseInt(langVer[1].trim()),
                    URI.create(parts[1].trim())));
            }
        }
    }

    public static LanguageServerRegistry instance() {
        return INSTANCE;
    }

    public List<Target> targets() {
        return targets;
    }

    public List<EndpointPair> pairs() {
        List<EndpointPair> pairs = new ArrayList<>();
        for (Target a : targets) {
            for (Target b : targets) {
                pairs.add(new EndpointPair(a, b));
            }
        }
        return pairs;
    }
}
