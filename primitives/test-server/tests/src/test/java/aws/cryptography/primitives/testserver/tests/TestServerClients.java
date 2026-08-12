package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * Client factory for the Primitives TestServer. Caches clients per endpoint.
 */
public final class TestServerClients {

    private static final Map<URI, PrimitivesTestServerClient> CLIENTS = new ConcurrentHashMap<>();

    private TestServerClients() {
    }

    public static PrimitivesTestServerClient forEndpoint(URI endpoint) {
        return CLIENTS.computeIfAbsent(endpoint, TestServerClients::build);
    }

    private static PrimitivesTestServerClient build(URI endpoint) {
        return PrimitivesTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
