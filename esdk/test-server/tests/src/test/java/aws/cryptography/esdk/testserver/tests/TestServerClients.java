package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * Provides the ONE generated Java Test_Client (Requirement 1.6) pointed at a base
 * endpoint URL. The {@code Tests} use this client exclusively; there is no
 * per-language client.
 *
 * <p>The client speaks the rpcv2Cbor protocol declared once at the service level
 * in the single source-of-truth model, over the JDK HTTP transport. The only
 * per-target input is the endpoint URL, which the Tests obtain from runtime
 * configuration (Requirement 7.3).
 *
 * <p>Clients are <strong>cached per endpoint</strong> and reused. A smithy-java
 * client (like an AWS SDK client) is thread-safe and designed to be shared; its
 * JDK {@code HttpClient} keeps a connection pool. The heavily-parameterized Tests
 * make thousands of calls, so building a fresh client per call would open an
 * equal number of short-lived connection pools and hammer each server with
 * connection churn — which surfaced as intermittent
 * {@code TransportException: ... received no bytes} (a reused/closed connection
 * or an overflowed listen backlog). One stable client per endpoint keeps a warm,
 * reusable connection pool and eliminates that churn.
 */
public final class TestServerClients {

    private static final Map<URI, ESDKTestServerClient> CLIENTS = new ConcurrentHashMap<>();

    private TestServerClients() {
    }

    /** @return a shared, reused Test_Client targeting {@code endpoint}. */
    public static ESDKTestServerClient forEndpoint(URI endpoint) {
        return CLIENTS.computeIfAbsent(endpoint, TestServerClients::build);
    }

    private static ESDKTestServerClient build(URI endpoint) {
        return ESDKTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
