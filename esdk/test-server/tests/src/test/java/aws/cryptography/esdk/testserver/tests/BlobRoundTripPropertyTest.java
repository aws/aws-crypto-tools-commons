package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.tests.EsdkClientConfigs.Scenario;
import java.util.LinkedHashMap;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
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
        // Plaintext-breadth property on a single server (the primary target's
        // self-pair); cross-language breadth is covered by MaterialsRoundTripTests.
        pair = LanguageServerRegistry.shared().selfPair();
    }

    // Feature: esdk-test-server, Property 1: Blob round-trip preserves plaintext byte-for-byte
    //
    // Task 14.3 broadens the generators feeding this property (the statement is
    // unchanged): in addition to arbitrary plaintext, it varies the offline ESDK
    // configuration — Raw-AES and Raw-RSA keyrings, multi-keyrings, the Default and
    // Required-Encryption-Context CMMs, and committing / non-committing / no-KDF
    // algorithm-suite selection — and the encryption context, so decrypt(encrypt(x))
    // == x is exercised across the config surface the Java ESDK supports offline
    // (Requirements 2.1, 2.2, 2.5, 4.2, 4.3, 4.4).
    @Property(tries = 100)
    void blobRoundTripPreservesPlaintextByteForByte(
            @ForAll("plaintexts") byte[] plaintext,
            @ForAll("scenarios") Scenario scenario,
            @ForAll("encryptionContexts") Map<String, String> encryptionContext) {
        // Ensure every key the scenario's CMM requires is present in the encryption
        // context (a Required-Encryption-Context CMM drops these from the header and
        // demands them again on decrypt); the same context is used on encrypt and
        // decrypt so the round trip is well-formed.
        Map<String, String> ec = new LinkedHashMap<>(encryptionContext);
        for (String requiredKey : scenario.requiredEncryptionContextKeys()) {
            ec.putIfAbsent(requiredKey, "required-value-for-" + requiredKey);
        }

        byte[] recovered = BlobRoundTrip.run(pair, plaintext, scenario, ec);
        assertArrayEquals(plaintext, recovered,
            "decrypt(encrypt(plaintext)) must equal the original plaintext for all inputs "
                + "(scenario: " + scenario.label() + ")");
    }

    /**
     * The offline, round-trip-compatible ESDK configurations to exercise. This
     * property is arbitrary-plaintext <em>offline</em> breadth, so it draws only
     * from {@link EsdkClientConfigs#offlineScenarios()} — the online, credential-
     * gated KMS scenarios are exercised (and skipped when unavailable) by
     * {@code MaterialsRoundTripTests}, not repeated here across 100 iterations.
     */
    @Provide
    Arbitrary<Scenario> scenarios() {
        return Arbitraries.of(EsdkClientConfigs.offlineScenarios());
    }

    /**
     * Arbitrary small encryption contexts. Keys and values are lowercase-letter
     * strings so they never collide with ESDK-reserved keys (for example the
     * {@code aws-crypto-public-key} added by signed suites) or with the scenarios'
     * required keys.
     */
    @Provide
    Arbitrary<Map<String, String>> encryptionContexts() {
        Arbitrary<String> tokens = Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(8);
        return Arbitraries.maps(tokens, tokens).ofMinSize(0).ofMaxSize(3);
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
