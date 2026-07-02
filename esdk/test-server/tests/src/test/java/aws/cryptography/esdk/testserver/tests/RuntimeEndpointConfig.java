package aws.cryptography.esdk.testserver.tests;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Resolves the target Language_Server endpoint(s) for the single {@code Tests}
 * suite from <em>runtime configuration only</em> (Requirement 7.3): pointing the
 * Tests at a different Language_Server is a runtime-configuration change with no
 * change to the Tests definition.
 *
 * <p>Configuration sources, in precedence order:
 * <ol>
 *   <li>System property {@code esdk.testserver.endpoints}</li>
 *   <li>Environment variable {@code ESDK_TESTSERVER_ENDPOINTS}</li>
 * </ol>
 * The value is a comma-separated list of base endpoint URLs (for example
 * {@code http://127.0.0.1:8080,http://127.0.0.1:8081}). The first entry is the
 * "encrypt" endpoint and the second (if present) is the "decrypt" endpoint; a
 * single entry is used for both sides of the round trip.
 *
 * <p>When no endpoint is configured, {@link #isManaged()} is {@code true}: for
 * the Java-only checkpoint the Tests boot one Java Language_Server in-process and
 * target it over the wire on both sides of the pair (the "pair" is the Java
 * server as both encrypt and decrypt endpoint). The orchestrator (a later task)
 * supplies real endpoints via this same runtime configuration, unchanged Tests.
 */
public final class RuntimeEndpointConfig {

    /** System property carrying a comma-separated list of base endpoint URLs. */
    public static final String ENDPOINTS_PROPERTY = "esdk.testserver.endpoints";

    /** Environment variable equivalent of {@link #ENDPOINTS_PROPERTY}. */
    public static final String ENDPOINTS_ENV = "ESDK_TESTSERVER_ENDPOINTS";

    private final List<String> endpoints;

    private RuntimeEndpointConfig(List<String> endpoints) {
        this.endpoints = endpoints;
    }

    /** Resolve configuration from the current runtime (system property / env). */
    public static RuntimeEndpointConfig fromRuntime() {
        Optional<String> raw = rawConfiguredValue();
        if (raw.isEmpty()) {
            return new RuntimeEndpointConfig(List.of());
        }
        List<String> parsed = Arrays.stream(raw.get().split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .toList();
        return new RuntimeEndpointConfig(parsed);
    }

    private static Optional<String> rawConfiguredValue() {
        String property = System.getProperty(ENDPOINTS_PROPERTY);
        if (property != null && !property.isBlank()) {
            return Optional.of(property);
        }
        String env = System.getenv(ENDPOINTS_ENV);
        if (env != null && !env.isBlank()) {
            return Optional.of(env);
        }
        return Optional.empty();
    }

    /**
     * @return {@code true} when no endpoint is configured, so the Tests must
     *     manage (boot) a local Java Language_Server for the checkpoint.
     */
    public boolean isManaged() {
        return endpoints.isEmpty();
    }

    /** @return the configured base endpoint URLs (empty when {@link #isManaged()}). */
    public List<String> endpoints() {
        return endpoints;
    }
}
