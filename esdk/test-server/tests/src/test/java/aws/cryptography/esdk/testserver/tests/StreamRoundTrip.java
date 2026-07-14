package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptStreamInput;
import aws.cryptography.esdk.testserver.client.model.EncryptStreamInput;
import java.nio.ByteBuffer;

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
 * <p>Both the example-based Test and the property-based Test (Property 15) drive
 * this single body, so there is exactly one definition of the stream round trip.
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
        String encryptClientId = encryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build()).getClientId();
        String decryptClientId = decryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build()).getClientId();

        // EncryptStream against one endpoint (Stream_Variant, Requirement 4.5). The
        // server drives the ESDK streaming encrypt API; the payload rides as a blob.
        ByteBuffer ciphertext = encryptClient.encryptStream(
            EncryptStreamInput.builder()
                .clientId(encryptClientId)
                .plaintext(ByteBuffer.wrap(plaintext))
                .build())
            .getCiphertext();

        // DecryptStream against the other endpoint (Stream_Variant, Requirement 4.6).
        ByteBuffer recovered = decryptClient.decryptStream(
            DecryptStreamInput.builder()
                .clientId(decryptClientId)
                .ciphertext(ciphertext)
                .build())
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
