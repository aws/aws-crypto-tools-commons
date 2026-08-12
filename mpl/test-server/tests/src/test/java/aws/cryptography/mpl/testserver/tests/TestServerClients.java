package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

public final class TestServerClients {

    private static final Map<URI, MPLTestServerClient> CLIENTS = new ConcurrentHashMap<>();

    private TestServerClients() {
    }

    public static MPLTestServerClient forEndpoint(URI endpoint) {
        return CLIENTS.computeIfAbsent(endpoint, TestServerClients::build);
    }

    private static MPLTestServerClient build(URI endpoint) {
        return MPLTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
