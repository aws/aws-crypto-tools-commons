package aws.cryptography.esdk.testserver.tests;

import java.net.URI;
import java.util.List;

/**
 * An (encrypt endpoint, decrypt endpoint) pair for a blob round trip, resolved
 * from {@link RuntimeEndpointConfig} (Requirement 7.3).
 *
 * <p>When runtime configuration supplies endpoints, the first is the encrypt
 * endpoint and the second (or the first again, if only one is configured) is the
 * decrypt endpoint. When no endpoint is configured (the Java-only checkpoint),
 * this boots one Java Language_Server in-process and uses it as BOTH the encrypt
 * and decrypt endpoint (Requirement 4.4, first-pass Java/Java pair).
 *
 * <p>Instances are {@link AutoCloseable}: closing shuts down any server this pair
 * booted. When endpoints come from configuration, closing is a no-op.
 */
public final class EndpointPair implements AutoCloseable {

    private final URI encryptEndpoint;
    private final URI decryptEndpoint;
    private final LocalJavaLanguageServer managedServer; // null when externally configured

    private EndpointPair(URI encryptEndpoint, URI decryptEndpoint, LocalJavaLanguageServer managedServer) {
        this.encryptEndpoint = encryptEndpoint;
        this.decryptEndpoint = decryptEndpoint;
        this.managedServer = managedServer;
    }

    /** Resolve a pair from runtime configuration, booting a local server if none is configured. */
    public static EndpointPair resolve(RuntimeEndpointConfig config) {
        if (config.isManaged()) {
            LocalJavaLanguageServer server = LocalJavaLanguageServer.start();
            return new EndpointPair(server.endpoint(), server.endpoint(), server);
        }
        List<String> endpoints = config.endpoints();
        URI encrypt = URI.create(endpoints.get(0));
        URI decrypt = URI.create(endpoints.get(endpoints.size() > 1 ? 1 : 0));
        return new EndpointPair(encrypt, decrypt, null);
    }

    public URI encryptEndpoint() {
        return encryptEndpoint;
    }

    public URI decryptEndpoint() {
        return decryptEndpoint;
    }

    @Override
    public void close() {
        if (managedServer != null) {
            managedServer.close();
        }
    }
}
