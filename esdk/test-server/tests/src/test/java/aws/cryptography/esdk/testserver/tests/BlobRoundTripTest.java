package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The blob round-trip Test (Task 5.2): for an endpoint pair, {@code CreateClient}
 * on each, {@code Encrypt} against one, {@code Decrypt} against the other, and
 * assert the recovered plaintext is byte-for-byte identical to the original
 * (Requirements 4.2, 4.3, 4.4, 4.8). First pass exercises the Blob_Variant only.
 *
 * <p>Endpoints come from runtime configuration; for the Java-only checkpoint the
 * pair is the in-process Java Language_Server as both the encrypt and decrypt
 * endpoint, driven over the real rpcv2Cbor wire protocol by the ONE generated
 * Java Test_Client.
 */
class BlobRoundTripTest {

    @Test
    @DisplayName("blob round-trip preserves an example plaintext byte-for-byte across an endpoint pair")
    void blobRoundTripPreservesExamplePlaintext() {
        byte[] plaintext = "esdk-test-server blob round-trip example plaintext".getBytes(StandardCharsets.UTF_8);
        try (EndpointPair pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime())) {
            byte[] recovered = BlobRoundTrip.run(pair, plaintext);
            assertArrayEquals(plaintext, recovered,
                "decrypt(encrypt(plaintext)) must equal the original plaintext");
        }
    }

    @Test
    @DisplayName("blob round-trip preserves the empty plaintext byte-for-byte")
    void blobRoundTripPreservesEmptyPlaintext() {
        byte[] empty = new byte[0];
        try (EndpointPair pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime())) {
            byte[] recovered = BlobRoundTrip.run(pair, empty);
            assertArrayEquals(empty, recovered,
                "the empty plaintext must round-trip to the empty plaintext (Requirement 4.4)");
        }
    }
}
