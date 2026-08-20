package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.testserver.tests.TestServerClientCache;
import java.net.URI;
import java.util.function.Supplier;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * The ESDK-side thin wrapper over the shared {@link TestServerClientCache}:
 * caches ONE generated Java Test_Client per base endpoint URL, built with the
 * rpcv2Cbor protocol declared once at the service level in the ESDK Smithy
 * model over the JDK HTTP transport. The Tests use this class exclusively;
 * there is no per-language client.
 *
 * <p>The generic cache carries the per-endpoint reuse rationale (thread-safe
 * client + JDK HttpClient connection pool + retry semantics); this class only
 * supplies the ESDK-specific builder function.
 */
public final class EsdkTestServerClients {

    private static final TestServerClientCache<ESDKTestServerClient> CACHE =
        new TestServerClientCache<>(EsdkTestServerClients::build);

    private EsdkTestServerClients() {
    }

    /** @return a shared, reused ESDK Test_Client targeting {@code endpoint}. */
    public static ESDKTestServerClient forEndpoint(URI endpoint) {
        return CACHE.forEndpoint(endpoint);
    }

    /** Run a single Test_Client RPC, retrying only a transport-level failure. */
    public static <T> T withRetry(Supplier<T> call) {
        return TestServerClientCache.withRetry(call);
    }

    private static ESDKTestServerClient build(URI endpoint) {
        return ESDKTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
