package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.tests.EsdkClientConfigs.Scenario;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The single round-trip class that runs every configuration scenario across the
 * full <strong>cross-language pairwise matrix</strong> of Language_Server targets
 * (design "Per-scenario config coverage" + "Cross-language blob round-trip").
 *
 * <p>Each round-trip test — a blob round-trip ({@link #blobRoundTrip}) and a
 * stream round-trip ({@link #streamRoundTrip}) — is a {@link ParameterizedTest}
 * over the product of {@link LanguageServerRegistry#pairs()} (every
 * {@code (encrypt target, decrypt target)} pair, including same-target pairs) and
 * {@link EsdkClientConfigs#scenarios()}. Every {@code (pair × scenario)} is one
 * named, deterministic execution — for example {@code blob[rawAes+default]
 * java-v3->python-v4} — so adding a language (another
 * {@code (language, majorVersion)} target) automatically fans every scenario out
 * across the new cross-language pairs with no change here.
 *
 * <p>With only Java configured (the managed / Java-only checkpoint) the matrix is
 * the single {@code java-v3 -> java-v3} pair, so this reduces to the prior
 * single-server per-scenario coverage.
 *
 * <p>The blob round-trip runs over every pair. The stream round-trip runs only
 * over pairs whose BOTH endpoints are Streaming_Capable (Requirements 4.9, 4.10):
 * with two Streaming_Capable servers (Java, Python) that is the full matrix; a
 * non-streaming server (a future Rust/Go/.NET) is simply excluded from the stream
 * pairs. Each execution asserts {@code decrypt(encrypt(x)) == x} byte-for-byte
 * over a small fixed representative plaintext set including the empty plaintext.
 *
 * <p>The KMS scenarios among {@link EsdkClientConfigs#scenarios()} are online and
 * required; here they additionally become cross-language KMS round trips (encrypt
 * on one language, decrypt on another) across the matrix.
 */
class MaterialsRoundTripTests {

    /** Blob round-trip cases: every pair × every scenario. */
    static List<Arguments> blobCases() {
        return casesOver(LanguageServerRegistry.shared().pairs());
    }

    /** Stream round-trip cases: every Streaming_Capable pair × every scenario. */
    static List<Arguments> streamCases() {
        List<EndpointPair> streamingPairs = LanguageServerRegistry.shared().pairs().stream()
            .filter(EndpointPair::isStreamingCapable)
            .toList();
        return casesOver(streamingPairs);
    }

    private static List<Arguments> casesOver(List<EndpointPair> pairs) {
        List<Arguments> cases = new ArrayList<>();
        for (EndpointPair pair : pairs) {
            for (Scenario scenario : EsdkClientConfigs.scenarios()) {
                cases.add(Arguments.of(pair, scenario));
            }
        }
        return cases;
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
     * Blob round-trip, run for every {@code (pair × scenario)}. One named execution
     * per case ({@code blob[<scenario>] <encrypt>-><decrypt>}); asserts {@code
     * decrypt(encrypt(x)) == x} byte-for-byte over the representative plaintexts
     * (Requirements 4.2, 4.3, 4.4, 8.1).
     */
    @ParameterizedTest(name = "blob[{1}] {0}")
    @MethodSource("blobCases")
    void blobRoundTrip(EndpointPair pair, Scenario scenario) {
        Map<String, String> ec = requiredContext(scenario);
        for (byte[] plaintext : representativePlaintexts()) {
            byte[] recovered = BlobRoundTrip.run(pair, plaintext, scenario, ec);
            assertArrayEquals(plaintext, recovered,
                "decrypt(encrypt(plaintext)) must equal the original plaintext "
                    + "(pair: " + pair + ", scenario: " + scenario.label() + ", plaintext length: "
                    + plaintext.length + ")");
        }
    }

    /**
     * Stream round-trip, run for every Streaming_Capable {@code (pair × scenario)}.
     * One named execution per case ({@code stream[<scenario>] <encrypt>-><decrypt>});
     * asserts {@code decryptStream(encryptStream(x)) == x} byte-for-byte over the
     * representative plaintexts (Requirements 4.5, 4.6, 4.9, 4.10).
     */
    @ParameterizedTest(name = "stream[{1}] {0}")
    @MethodSource("streamCases")
    void streamRoundTrip(EndpointPair pair, Scenario scenario) {
        Map<String, String> ec = requiredContext(scenario);
        for (byte[] plaintext : representativePlaintexts()) {
            byte[] recovered = StreamRoundTrip.run(pair, plaintext, scenario, ec);
            assertArrayEquals(plaintext, recovered,
                "decryptStream(encryptStream(plaintext)) must equal the original plaintext "
                    + "(pair: " + pair + ", scenario: " + scenario.label() + ", plaintext length: "
                    + plaintext.length + ")");
        }
    }
}
