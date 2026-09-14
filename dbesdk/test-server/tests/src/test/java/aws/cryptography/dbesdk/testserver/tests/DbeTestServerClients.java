package aws.cryptography.dbesdk.testserver.tests;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.testserver.tests.TestServerClientCache;
import java.net.URI;
import java.util.function.Supplier;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * The DB-ESDK-side thin wrapper over the shared {@link TestServerClientCache}:
 * caches ONE generated Java Test_Client per base endpoint URL, built with the
 * rpcv2Cbor protocol declared once at the service level in the DB-ESDK Smithy
 * model over the JDK HTTP transport. The Tests use this class exclusively;
 * there is no per-language client.
 *
 * <p>The generic cache carries the per-endpoint reuse rationale (thread-safe
 * client + JDK HttpClient connection pool + retry semantics); this class only
 * supplies the DB-ESDK-specific builder function.
 */
public final class DbeTestServerClients {

    private static final TestServerClientCache<DBESDKTestServerClient> CACHE =
        new TestServerClientCache<>(DbeTestServerClients::build);

    private DbeTestServerClients() {
    }

    /** @return a shared, reused DB-ESDK Test_Client targeting {@code endpoint}. */
    public static DBESDKTestServerClient forEndpoint(URI endpoint) {
        return CACHE.forEndpoint(endpoint);
    }

    /** Run a single Test_Client RPC, retrying only a transport-level failure. */
    public static <T> T withRetry(Supplier<T> call) {
        return TestServerClientCache.withRetry(call);
    }

    private static DBESDKTestServerClient build(URI endpoint) {
        return DBESDKTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
