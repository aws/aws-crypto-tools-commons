package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Set;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.BeforeContainer;

/**
 * Property-based Test for the single-server stream round trip (Task 14.2).
 *
 * <p>The Stream_Variant payload rides on the wire as a plain {@code Blob} (not a
 * Smithy {@code @streaming} member, because stock smithy-java 1.4.0 does not
 * transmit {@code @streaming} members over rpcv2-CBOR); the streaming semantics
 * live entirely server-side, where the Java Language_Server wraps the received
 * blob in a stream, drives the real ESDK streaming encrypt/decrypt API, and
 * collects the streamed output back into a blob (Requirement 4.1). The round trip
 * therefore exercises the ESDK streaming code path on both legs over the real
 * rpcv2Cbor wire hop.
 *
 * <p>Feature: esdk-test-server, Property 15: Stream round-trip preserves plaintext byte-for-byte
 *
 * <p>For any plaintext byte sequence (including the empty plaintext, binary data,
 * and large inputs), decrypting the ciphertext stream produced by the stream
 * {@code Encrypt} of a Streaming_Capable client with the stream {@code Decrypt} of
 * the same client — on the same Streaming_Capable Java Language_Server — yields a
 * plaintext byte-for-byte identical to the original.
 *
 * <p>Validates: Requirements 4.5, 4.6, 4.9
 *
 * <p>The endpoint pair is resolved once from runtime configuration and reused
 * across all generated examples. For the offline Java hardening pass that pair is
 * one in-process Java Language_Server (encrypt endpoint == decrypt endpoint, the
 * same Streaming_Capable server), driven over the real rpcv2Cbor wire protocol by
 * the ONE generated Java Test_Client. A cross-language stream round-trip is
 * deferred until at least two Streaming_Capable servers exist (Requirement 4.10).
 */
class StreamRoundTripPropertyTest {

    private static TargetPair pair;

    @BeforeContainer
    static void bootEndpoints() {
        // Single-server stream plaintext-breadth property on the primary target's
        // self-pair; cross-language stream breadth lives in
        // MaterialsRoundTripTests over every pair, gated per combination.
        pair = LanguageServerRegistry.shared().selfPair();
        // This container is associated with the streaming Feature (Requirements
        // 9.1, 9.2): gate before any Language_Server operation. A TestAbortedException
        // thrown here aborts the whole container, surfacing as skipped in the
        // platform reports (Requirement 9.5).
        FeatureGate.require(Set.of("streaming"), pair);
    }

    // Feature: esdk-test-server, Property 15: Stream round-trip preserves plaintext byte-for-byte
    @Property(tries = 100)
    void streamRoundTripPreservesPlaintextByteForByte(@ForAll("plaintexts") byte[] plaintext) {
        byte[] recovered = StreamRoundTrip.run(pair, plaintext);
        assertArrayEquals(plaintext, recovered,
            "decryptStream(encryptStream(plaintext)) must equal the original plaintext for all inputs");
    }

    /**
     * Arbitrary plaintexts spanning the input space that matters for the stream
     * round trip: the empty plaintext, small/medium arbitrary binary blobs, and
     * large blobs (bounded so 100+ iterations stay fast). Bytes are unconstrained
     * so arbitrary binary content — including NULs and non-UTF-8 sequences — is
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
