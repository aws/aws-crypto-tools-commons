package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

/**
 * Property-based Test for the blob round trip (Task 5.3).
 *
 * <p>Feature: esdk-test-server, Property 1: Blob round-trip preserves plaintext byte-for-byte
 *
 * <p>For any plaintext byte sequence (including the empty plaintext, binary data,
 * and large inputs), decrypting the ciphertext produced by the blob {@code Encrypt}
 * of one configured client with the blob {@code Decrypt} of a second compatible
 * client yields a plaintext byte-for-byte identical to the original.
 *
 * <p>Validates: Requirements 4.2, 4.3, 4.4
 *
 * <p>The endpoint pair is resolved once from runtime configuration and reused
 * across all generated examples. For the Java-only checkpoint that pair is one
 * in-process Java Language_Server (encrypt endpoint == decrypt endpoint), driven
 * over the real rpcv2Cbor wire protocol by the ONE generated Java Test_Client.
 */
class BlobRoundTripPropertyTest {

    private static EndpointPair pair;

    @BeforeContainer
    static void bootEndpoints() {
        pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime());
    }

    @AfterContainer
    static void shutdownEndpoints() {
        if (pair != null) {
            pair.close();
        }
    }

    // Feature: esdk-test-server, Property 1: Blob round-trip preserves plaintext byte-for-byte
    @Property(tries = 100)
    void blobRoundTripPreservesPlaintextByteForByte(@ForAll("plaintexts") byte[] plaintext) {
        byte[] recovered = BlobRoundTrip.run(pair, plaintext);
        assertArrayEquals(plaintext, recovered,
            "decrypt(encrypt(plaintext)) must equal the original plaintext for all inputs");
    }

    /**
     * Arbitrary plaintexts spanning the input space that matters for the round
     * trip: the empty plaintext, small/medium arbitrary binary blobs, and large
     * blobs (bounded so 100+ iterations stay fast). Bytes are unconstrained so
     * arbitrary binary content — including NULs and non-UTF-8 sequences — is
     * covered.
     */
    @Provide
    Arbitrary<byte[]> plaintexts() {
        Arbitrary<byte[]> emptyAndSmall = Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(256);
        Arbitrary<byte[]> medium = Arbitraries.bytes().array(byte[].class).ofMinSize(257).ofMaxSize(8192);
        Arbitrary<byte[]> large = Arbitraries.bytes().array(byte[].class).ofMinSize(8193).ofMaxSize(65536);
        // Weight toward smaller inputs (fast) while still regularly exercising the
        // empty plaintext and large blobs.
        return Arbitraries.frequencyOf(
            net.jqwik.api.Tuple.of(6, emptyAndSmall),
            net.jqwik.api.Tuple.of(3, medium),
            net.jqwik.api.Tuple.of(1, large));
    }
}
