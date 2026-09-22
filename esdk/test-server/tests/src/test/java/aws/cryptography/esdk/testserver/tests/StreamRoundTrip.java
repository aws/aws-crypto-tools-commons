package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptStreamInput;
import aws.cryptography.esdk.testserver.client.model.EncryptStreamInput;
import aws.cryptography.esdk.testserver.tests.EsdkClientConfigs.Scenario;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * The shared single-server stream round-trip: {@code CreateClient} on the
 * Streaming_Capable endpoint(s) of a pair, {@code EncryptStream} the plaintext
 * against the encrypt endpoint, then {@code DecryptStream} the resulting
 * ciphertext against the decrypt endpoint, and return the recovered plaintext
 * (Requirements 4.5, 4.6, 4.9). Exercises the Stream_Variant over the real wire
 * protocol via the ONE generated Java Test_Client.
 *
 * <p>The Stream_Variant payload rides on the wire as a plain {@code Blob} (a
 * {@link ByteBuffer}), NOT a Smithy {@code @streaming} member, because stock
 * smithy-java 1.4.0 does not transmit {@code @streaming} members over rpcv2-CBOR
 * (Requirement 4.1). The streaming semantics live entirely server-side: the
 * Language_Server wraps the received blob in a stream, drives the ESDK streaming
 * encrypt/decrypt API, and collects the streamed output back into a blob. This
 * round trip therefore exercises the ESDK streaming code path on both legs while
 * the wire carries ordinary blobs.
 *
 * <p>The endpoint is data-driven through {@link EndpointPair} exactly like
 * {@link BlobRoundTrip}: today the only Streaming_Capable server is the Java
 * Language_Server, so the pair's encrypt and decrypt endpoints are the SAME Java
 * server and this is the in-scope single-server stream round-trip (Requirement
 * 4.9). When a second Streaming_Capable server is added, the same body drives a
 * cross-language stream round-trip across a compatible pair (Requirement 4.10)
 * with no change here.
 *
 * <p>Both the per-configuration {@code MaterialsRoundTripTests#streamRoundTrip}
 * (one named execution per scenario) and the property-based Test (Property 15)
 * drive this single body, so there is exactly one definition of the stream round
 * trip.
 *
 * <p>Each RPC goes through {@link TestServerClients#withRetry} so a transient
 * transport failure is retried on the test side rather than failing the run.
 */
public final class StreamRoundTrip {

    private StreamRoundTrip() {
    }

    /**
     * Encrypt {@code plaintext} as a stream against the pair's encrypt endpoint and
     * decrypt the ciphertext stream against its decrypt endpoint, returning the
     * recovered plaintext bytes.
     */
    public static byte[] run(EndpointPair pair, byte[] plaintext) {
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        // CreateClient on each endpoint; each returns a ClientId referencing a
        // configured, offline Raw-AES ESDK client (Requirement 3.1).
        String encryptClientId = TestServerClients.withRetry(() -> encryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build())).getClientId();
        String decryptClientId = TestServerClients.withRetry(() -> decryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build())).getClientId();

        // EncryptStream against one endpoint (Stream_Variant, Requirement 4.5). The
        // server drives the ESDK streaming encrypt API; the payload rides as a blob.
        EncryptStreamInput encryptRequest = EncryptStreamInput.builder()
            .clientId(encryptClientId)
            .plaintext(ByteBuffer.wrap(plaintext))
            .build();
        ByteBuffer ciphertext =
            TestServerClients.withRetry(() -> encryptClient.encryptStream(encryptRequest))
                .getCiphertext();

        // DecryptStream against the other endpoint (Stream_Variant, Requirement 4.6).
        DecryptStreamInput decryptRequest = DecryptStreamInput.builder()
            .clientId(decryptClientId)
            .ciphertext(ciphertext)
            .build();
        ByteBuffer recovered =
            TestServerClients.withRetry(() -> decryptClient.decryptStream(decryptRequest))
                .getPlaintext();

        return toArray(recovered);
    }

    /**
     * Broadened stream round-trip: the same single body as {@link
     * #run(EndpointPair, byte[])}, but driven by an offline {@link Scenario}
     * (arbitrary supported keyring/CMM/algorithm-suite combination) and an
     * encryption context, mirroring {@link BlobRoundTrip#run(EndpointPair, byte[],
     * Scenario, Map)}. The scenario's {@code config} builds the encrypt client and
     * {@link Scenario#decryptConfigOrDefault()} builds the decrypt client (usually
     * the same config), so the material is compatible and {@code
     * decryptStream(encryptStream(x)) == x} holds byte-for-byte (Requirements 4.5,
     * 4.6, 4.9).
     *
     * <p>As with the blob variant, the {@code encryptionContext} is applied on
     * {@code EncryptStream} and supplied again on {@code DecryptStream} (so a
     * Required-Encryption-Context CMM can reconstruct its required keys); the
     * scenario's optional algorithm-suite override is applied on encrypt only
     * (decrypt derives the suite from the message header). The payload still rides
     * as a plain blob on the wire; the Java server drives the ESDK streaming API
     * internally (wrap-bytes → streaming encrypt/decrypt → collect-bytes) on both
     * legs.
     */
    public static byte[] run(EndpointPair pair, byte[] plaintext, Scenario scenario,
                             Map<String, String> encryptionContext) {
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        String encryptClientId = TestServerClients.withRetry(() -> encryptClient.createClient(
            CreateClientInput.builder().config(scenario.config()).build())).getClientId();
        String decryptClientId = TestServerClients.withRetry(() -> decryptClient.createClient(
            CreateClientInput.builder().config(scenario.decryptConfigOrDefault()).build()))
            .getClientId();

        EncryptStreamInput.Builder encryptInput = EncryptStreamInput.builder()
            .clientId(encryptClientId)
            .plaintext(ByteBuffer.wrap(plaintext));
        if (!encryptionContext.isEmpty()) {
            encryptInput.encryptionContext(encryptionContext);
        }
        if (scenario.algorithmSuiteId() != null) {
            encryptInput.algorithmSuiteId(scenario.algorithmSuiteId());
        }
        EncryptStreamInput encryptRequest = encryptInput.build();
        ByteBuffer ciphertext =
            TestServerClients.withRetry(() -> encryptClient.encryptStream(encryptRequest))
                .getCiphertext();

        DecryptStreamInput.Builder decryptInput = DecryptStreamInput.builder()
            .clientId(decryptClientId)
            .ciphertext(ciphertext);
        if (!encryptionContext.isEmpty()) {
            decryptInput.encryptionContext(encryptionContext);
        }
        DecryptStreamInput decryptRequest = decryptInput.build();
        ByteBuffer recovered =
            TestServerClients.withRetry(() -> decryptClient.decryptStream(decryptRequest))
                .getPlaintext();

        return toArray(recovered);
    }

    private static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
