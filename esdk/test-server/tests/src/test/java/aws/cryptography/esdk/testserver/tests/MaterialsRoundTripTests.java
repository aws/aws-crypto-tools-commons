package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.tests.EsdkClientConfigs.Scenario;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The single per-configuration round-trip class for the offline Java hardening
 * pass (design "Per-scenario config coverage for the Java hardening pass").
 *
 * <p>This class holds every per-configuration round-trip. It currently contains
 * two round-trip tests — a blob round-trip ({@link #blobRoundTrip}) and a stream
 * round-trip ({@link #streamRoundTrip}) — and <strong>each</strong> of them is
 * executed against <strong>every</strong> offline configuration {@link Scenario}
 * from {@link EsdkClientConfigs#scenarios()}. Because JUnit 5.11.3 predates
 * {@code @ParameterizedClass}, the per-scenario fan-out is achieved by the
 * convention that each round-trip test method is itself a
 * {@link ParameterizedTest} + {@link MethodSource} over the scenarios. Every
 * {@code (test × scenario)} pair is therefore a distinct, named, deterministic
 * execution in the report — for example {@code blob[rawRsa+default]},
 * {@code stream[multi(rawAes,rawRsa)+default]} — and is <strong>guaranteed to
 * run</strong> on every pass. This class is the mechanism that guarantees
 * per-config coverage.
 *
 * <p>As more round-trip tests are added they join this same class, so each new
 * round-trip is <strong>automatically run against every configuration</strong>
 * without any further wiring.
 *
 * <p>Each execution asserts {@code decrypt(encrypt(x)) == x} byte-for-byte — for
 * the blob round-trip (Requirements 4.2, 4.3, 4.4) and for the stream round-trip
 * (Requirements 4.5, 4.6, 4.9) — over a small, FIXED representative set of
 * plaintexts (the empty plaintext, a small text blob, and a ~8KB binary blob;
 * deterministic content, not random). This drives real config marshalling (the
 * tagged-union config surface, incl. the recursive multi-keyring nesting of
 * Property 7) and the real ESDK Java code paths over the real rpcv2Cbor HTTP hop
 * via the ONE generated Java Test_Client. Fully offline: no AWS/KMS/network.
 *
 * <p>The stream round-trip preserves the Stream_Variant blob-on-the-wire
 * semantics: the payload rides as a plain {@code Blob} on the wire (not a Smithy
 * {@code @streaming} member, which stock smithy-java 1.4.0 does not transmit over
 * rpcv2-CBOR) and the Java server drives the ESDK streaming API internally
 * (wrap-bytes → streaming encrypt/decrypt → collect-bytes) on both legs. The
 * endpoint is data-driven through {@link EndpointPair}: today the only
 * Streaming_Capable server is the Java Language_Server, so the pair's encrypt and
 * decrypt endpoints are the SAME Java server; a cross-language stream round-trip
 * is deferred until at least two Streaming_Capable servers exist (Requirement
 * 4.10).
 *
 * <p>The jqwik property tests remain <strong>separate</strong> for
 * arbitrary-plaintext breadth: {@code BlobRoundTripPropertyTest} (Property 1) and
 * {@code StreamRoundTripPropertyTest} (Property 15) each generate arbitrary
 * plaintext across &ge;100 iterations, but they are explicitly not the mechanism
 * that guarantees per-config coverage — this class is. The property statements
 * are unchanged; the two are complementary.
 *
 * <p>The {@link EndpointPair} is resolved once for the whole class ({@link
 * BeforeAll}/{@link AfterAll}) — for the offline Java hardening pass that pair is
 * the in-process Java Language_Server as both the encrypt and decrypt endpoint —
 * mirroring the lifecycle of the other Tests.
 */
class MaterialsRoundTripTests {

    private static EndpointPair pair;

    @BeforeAll
    static void bootEndpoints() {
        pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime());
    }

    @AfterAll
    static void shutdownEndpoints() {
        if (pair != null) {
            pair.close();
        }
    }

    /**
     * The offline, round-trip-compatible scenarios shared by every round-trip test
     * in this class. Each becomes one named parameterized execution per test;
     * {@link Scenario#toString()} supplies the label inside the {@code blob[...]} /
     * {@code stream[...]} name.
     */
    static List<Scenario> scenarios() {
        return EsdkClientConfigs.scenarios();
    }

    /**
     * A small, fixed, representative set of plaintexts exercised by every scenario
     * for every round-trip test: the empty plaintext (Requirements 4.4, 4.9), a
     * small text blob, and a ~8KB binary blob (deterministic content, not random).
     */
    private static List<byte[]> representativePlaintexts() {
        byte[] empty = new byte[0];
        byte[] smallText =
            "esdk-test-server per-scenario round-trip plaintext".getBytes(StandardCharsets.UTF_8);
        byte[] largerBinary = new byte[8 * 1024 + 13];
        for (int i = 0; i < largerBinary.length; i++) {
            largerBinary[i] = (byte) (i * 31 + 7);
        }
        return List.of(empty, smallText, largerBinary);
    }

    /**
     * Build the encryption context every scenario needs: supply every key the
     * scenario's CMM requires (a Required-Encryption-Context CMM drops these from
     * the header and demands them again on decrypt). The same context is used on
     * encrypt and decrypt so the round trip is well-formed; empty for scenarios
     * with no required keys.
     */
    private static Map<String, String> requiredContext(Scenario scenario) {
        Map<String, String> ec = new LinkedHashMap<>();
        for (String requiredKey : scenario.requiredEncryptionContextKeys()) {
            ec.put(requiredKey, "required-value-for-" + requiredKey);
        }
        return ec;
    }

    /**
     * Blob round-trip, run against every offline scenario. One named execution per
     * scenario ({@code blob[<scenario>]}); asserts {@code decrypt(encrypt(x)) == x}
     * byte-for-byte over the representative plaintexts (Requirements 4.2, 4.3, 4.4).
     */
    @ParameterizedTest(name = "blob[{0}]")
    @MethodSource("scenarios")
    void blobRoundTrip(Scenario scenario) {
        Map<String, String> ec = requiredContext(scenario);
        for (byte[] plaintext : representativePlaintexts()) {
            byte[] recovered = BlobRoundTrip.run(pair, plaintext, scenario, ec);
            assertArrayEquals(plaintext, recovered,
                "decrypt(encrypt(plaintext)) must equal the original plaintext "
                    + "(scenario: " + scenario.label() + ", plaintext length: "
                    + plaintext.length + ")");
        }
    }

    /**
     * Stream round-trip, run against every offline scenario. One named execution
     * per scenario ({@code stream[<scenario>]}); asserts {@code
     * decryptStream(encryptStream(x)) == x} byte-for-byte over the representative
     * plaintexts on the same Streaming_Capable Java server (Requirements 4.5, 4.6,
     * 4.9).
     */
    @ParameterizedTest(name = "stream[{0}]")
    @MethodSource("scenarios")
    void streamRoundTrip(Scenario scenario) {
        Map<String, String> ec = requiredContext(scenario);
        for (byte[] plaintext : representativePlaintexts()) {
            byte[] recovered = StreamRoundTrip.run(pair, plaintext, scenario, ec);
            assertArrayEquals(plaintext, recovered,
                "decryptStream(encryptStream(plaintext)) must equal the original plaintext "
                    + "(scenario: " + scenario.label() + ", plaintext length: "
                    + plaintext.length + ")");
        }
    }
}
