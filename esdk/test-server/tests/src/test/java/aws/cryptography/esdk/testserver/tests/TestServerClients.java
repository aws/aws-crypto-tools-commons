package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import java.net.URI;
import software.amazon.smithy.java.client.http.JavaHttpClientTransport;

/**
 * Builds the ONE generated Java Test_Client (Requirement 1.6) pointed at a base
 * endpoint URL. The {@code Tests} use this client exclusively; there is no
 * per-language client.
 *
 * <p>The client speaks the rpcv2Cbor protocol declared once at the service level
 * in the single source-of-truth model, over the JDK HTTP transport. The only
 * per-target input is the endpoint URL, which the Tests obtain from runtime
 * configuration (Requirement 7.3).
 */
public final class TestServerClients {

    private TestServerClients() {
    }

    /** Build a Test_Client targeting {@code endpoint}. */
    public static ESDKTestServerClient forEndpoint(URI endpoint) {
        return ESDKTestServerClient.builder()
            .endpoint(endpoint.toString())
            .transport(new JavaHttpClientTransport())
            .build();
    }
}
