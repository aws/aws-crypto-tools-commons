package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The single-server stream round-trip Test (Task 14.1): {@code CreateClient},
 * {@code EncryptStream}, then {@code DecryptStream} on the SAME Streaming_Capable
 * Java server, asserting the recovered stream plaintext is byte-for-byte
 * identical to the original (Requirements 4.5, 4.6, 4.9). Fully offline: a
 * Raw-AES / Default-CMM config with no AWS/KMS/network.
 *
 * <p>Endpoints come from runtime configuration; for the offline Java hardening
 * pass the pair is the in-process Java Language_Server as both the encrypt and
 * decrypt endpoint (the same Streaming_Capable server), driven over the real
 * rpcv2Cbor wire protocol by the ONE generated Java Test_Client.
 *
 * <p>The Stream_Variant payload rides on the wire as a plain {@code Blob} (not a
 * Smithy {@code @streaming} member, because stock smithy-java 1.4.0 does not
 * transmit {@code @streaming} members over rpcv2-CBOR); the streaming semantics
 * live entirely server-side — the Java Language_Server wraps the received blob in
 * a stream, drives the real ESDK streaming encrypt/decrypt API, and collects the
 * streamed output back into a blob (Requirement 4.1). This round trip therefore
 * exercises the ESDK streaming code path on both legs over the real HTTP hop.
 */
class StreamRoundTripTest {

    @Test
    @DisplayName("stream round-trip preserves an example plaintext byte-for-byte on the same Java server")
    void streamRoundTripPreservesExamplePlaintext() {
        byte[] plaintext =
            "esdk-test-server stream round-trip example plaintext".getBytes(StandardCharsets.UTF_8);
        try (EndpointPair pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime())) {
            byte[] recovered = StreamRoundTrip.run(pair, plaintext);
            assertArrayEquals(plaintext, recovered,
                "decryptStream(encryptStream(plaintext)) must equal the original plaintext");
        }
    }

    @Test
    @DisplayName("stream round-trip preserves the empty plaintext byte-for-byte")
    void streamRoundTripPreservesEmptyPlaintext() {
        byte[] empty = new byte[0];
        try (EndpointPair pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime())) {
            byte[] recovered = StreamRoundTrip.run(pair, empty);
            assertArrayEquals(empty, recovered,
                "the empty plaintext must round-trip to the empty plaintext (Requirement 4.9)");
        }
    }

    @Test
    @DisplayName("stream round-trip preserves a large binary plaintext byte-for-byte")
    void streamRoundTripPreservesLargeBinaryPlaintext() {
        byte[] large = new byte[64 * 1024 + 7];
        for (int i = 0; i < large.length; i++) {
            large[i] = (byte) (i * 31 + 7);
        }
        try (EndpointPair pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime())) {
            byte[] recovered = StreamRoundTrip.run(pair, large);
            assertArrayEquals(large, recovered,
                "a large binary plaintext must stream round-trip byte-for-byte");
        }
    }
}
