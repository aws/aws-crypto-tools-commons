package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.testserver.tests.TestServerClientCache;
import java.net.URI;
import java.util.function.Supplier;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * The primitives-side thin wrapper over the shared {@link TestServerClientCache}:
 * caches ONE generated Java Test_Client per base endpoint URL, built with the
 * rpcv2Cbor protocol declared once at the service level in the primitives
 * Smithy model over the JDK HTTP transport. The Tests use this class
 * exclusively; there is no per-language client.
 *
 * <p>The generic cache carries the per-endpoint reuse rationale (thread-safe
 * client + JDK HttpClient connection pool + retry semantics); this class only
 * supplies the primitives-specific builder function.
 */
public final class PrimitivesTestServerClients {

    private static final TestServerClientCache<PrimitivesTestServerClient> CACHE =
        new TestServerClientCache<>(PrimitivesTestServerClients::build);

    private PrimitivesTestServerClients() {
    }

    /** @return a shared, reused primitives Test_Client targeting {@code endpoint}. */
    public static PrimitivesTestServerClient forEndpoint(URI endpoint) {
        return CACHE.forEndpoint(endpoint);
    }

    /** Run a single Test_Client RPC, retrying only a transport-level failure. */
    public static <T> T withRetry(Supplier<T> call) {
        return TestServerClientCache.withRetry(call);
    }

    private static PrimitivesTestServerClient build(URI endpoint) {
        return PrimitivesTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
