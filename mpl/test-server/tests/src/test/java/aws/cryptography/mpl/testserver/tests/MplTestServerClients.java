package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.testserver.tests.TestServerClientCache;
import java.net.URI;
import java.util.function.Supplier;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * The MPL-side thin wrapper over the shared {@link TestServerClientCache}:
 * caches ONE generated Java Test_Client per base endpoint URL, built with the
 * rpcv2Cbor protocol declared once at the service level in the MPL Smithy
 * model over the JDK HTTP transport. The Tests use this class exclusively;
 * there is no per-language client.
 *
 * <p>The generic cache carries the per-endpoint reuse rationale (thread-safe
 * client + JDK HttpClient connection pool + retry semantics); this class only
 * supplies the MPL-specific builder function.
 */
public final class MplTestServerClients {

    private static final TestServerClientCache<MPLTestServerClient> CACHE =
        new TestServerClientCache<>(MplTestServerClients::build);

    private MplTestServerClients() {
    }

    /** @return a shared, reused MPL Test_Client targeting {@code endpoint}. */
    public static MPLTestServerClient forEndpoint(URI endpoint) {
        return CACHE.forEndpoint(endpoint);
    }

    /** Run a single Test_Client RPC, retrying only a transport-level failure. */
    public static <T> T withRetry(Supplier<T> call) {
        return TestServerClientCache.withRetry(call);
    }

    private static MPLTestServerClient build(URI endpoint) {
        return MPLTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
