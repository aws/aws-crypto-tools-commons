package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Encryption-context behavior conformance across the configured Language_Server
 * targets. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>EC-010</b> — encrypt rejects a caller-supplied encryption context that
 *       contains the reserved {@code aws-crypto-public-key} key
 *       ({@code spec/client-apis/encrypt.md#encryption-context}). Encrypt is a
 *       per-server property, so it runs against every target.</li>
 *   <li><b>EC-020</b> — decrypt with the exact reproduced context recovers the
 *       plaintext ({@code spec/client-apis/decrypt.md#get-the-decryption-materials}).
 *       A round trip, so it runs over the cross-language pairwise matrix.</li>
 *   <li><b>EC-023</b> — a mismatched reproduced value is rejected (same spec
 *       section). Decrypt-side rows ({@link ReferenceImplementation#decryptSide}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES / Default CMM). ESDK-originated failures surface as a
 * modeled {@link ESDKClientError}.
 */
class EncryptionContextBehaviorTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server encryption-context plaintext".getBytes(StandardCharsets.UTF_8);
    private static final String RESERVED_KEY = "aws-crypto-public-key";

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(Set.of("raw-aes"));
    }

    /**
     * EC-010: a caller-supplied encryption context containing the reserved
     * {@code aws-crypto-public-key} key must make encrypt fail. Per-server property.
     */
    @ParameterizedTest(name = "reservedEcKeyRejected {0}")
    @MethodSource("targets")
    void encryptRejectsReservedEncryptionContextKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        Map<String, String> reserved = new LinkedHashMap<>();
        reserved.put(RESERVED_KEY, "any-value");
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, reserved, null, null),
            "encrypt with a reserved '" + RESERVED_KEY + "' encryption-context key must be "
                + "rejected as an ESDKClientError (" + target + ")");
    }

    /**
     * EC-020: decrypt succeeds when the reproduced encryption context exactly matches
     * what encrypt stored in the header. Cross-language matrix.
     */
    @ParameterizedTest(name = "reproducedEcMatchDecrypts {0}")
    @MethodSource("pairs")
    void decryptSucceedsWithMatchingReproducedContext(EndpointPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        Map<String, String> ec = Map.of("purpose", "test", "tenant", "acme");
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, null, null);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, ec);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt with the exact reproduced encryption context must recover the plaintext ("
                + pair + ")");
    }

    /**
     * EC-023: decrypt must fail when the reproduced encryption context mismatches the
     * header — here a present key given a different value. Asserts only the decryptor's
     * verification, so it runs decrypt-side (the matching-context round trip above keeps
     * the pairwise producer coverage).
     */
    @ParameterizedTest(name = "reproducedEcMismatchRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsMismatchedReproducedContext(ReferencePair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair.asEndpointPair());
        Map<String, String> ec = Map.of("purpose", "test");
        Map<String, String> wrong = Map.of("purpose", "tampered");
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, null, null);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, wrong),
            "decrypt with a reproduced encryption context that changes a value must be rejected "
                + "as an ESDKClientError (" + pair + ")");
    }

    /**
     * EC-035: an encryption context with high Unicode code points round-trips (the ESDK sorts the
     * context by unsigned UTF-8 bytes before binding it into the header AAD). Cross-language matrix.
     */
    @ParameterizedTest(name = "highCodepointEcRoundTrips {0}")
    @MethodSource("pairs")
    void encryptionContextWithHighCodepointsRoundTrips(EndpointPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        Map<String, String> ec = Map.of(
            "\u65e5\u672c\u8a9e", "value",          // CJK key
            "key-\ud83d\udd11", "\ud83d\ude80");    // astral-plane (emoji) key and value
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, null, null);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, ec);
        assertArrayEquals(PLAINTEXT, recovered,
            "an encryption context with high Unicode code points must round-trip (" + pair + ")");
    }

    /**
     * The whole {@code aws-crypto-} prefix is reserved, not only the exact
     * {@code aws-crypto-public-key} key that EC-010 covers: {@code encrypt.md} requires the
     * encryption operation to fail for any caller encryption-context key beginning with
     * {@code aws-crypto-} ({@code spec/client-apis/encrypt.md#encryption-context}). Per-server
     * property. Added by gap analysis; ledgered because current servers special-case only the
     * public-key rather than the whole prefix, so the gate re-activates the assertion if a server
     * starts enforcing it.
     */
    @ParameterizedTest(name = "reservedPrefixEcKeyRejected {0}")
    @MethodSource("targets")
    void encryptRejectsReservedPrefixEncryptionContextKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        Map<String, String> reserved = new LinkedHashMap<>();
        reserved.put("aws-crypto-not-a-real-reserved-key", "any-value");
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        KnownBugGate.gate("encrypt-accepts-reserved-prefix-encryption-context-key", target.language(),
            () -> assertThrows(ESDKClientError.class,
                () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, reserved, null, null),
                "encrypt with an 'aws-crypto-' prefixed encryption-context key must be rejected as an "
                    + "ESDKClientError (" + target + ")"));
    }

    /**
     * The reservation is exactly the {@code aws-crypto-} prefix: {@code aws-crypto} with no
     * trailing hyphen does not begin with it, so it is an ordinary caller key that must be accepted
     * and round-trip ({@code spec/client-apis/encrypt.md#encryption-context}). Guards against a
     * server over-blocking on a substring. Added by gap analysis.
     */
    @ParameterizedTest(name = "nonReservedPrefixBoundaryAccepted {0}")
    @MethodSource("targets")
    void encryptAcceptsKeyThatDoesNotBeginWithReservedPrefix(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        Map<String, String> ec = Map.of("aws-crypto", "no-trailing-hyphen-is-not-reserved");
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, ec, null, null);
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(target.endpoint(), config, ciphertext),
            target + ": a key that does not begin with 'aws-crypto-' must be accepted and round-trip");
    }
}
