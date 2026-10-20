package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
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
 *   <li><b>EC-020 / EC-023</b> — decrypt verifies the reproduced encryption context
 *       against the header: the exact context recovers the plaintext, a mismatched
 *       value is rejected
 *       ({@code spec/client-apis/decrypt.md#get-the-decryption-materials}). Runs over
 *       the cross-language pairwise matrix.</li>
 * </ul>
 *
 * <p>Encryption-context behavior is keyring-independent, so each combination runs once under the
 * keyring both endpoints support ({@link ConformanceKeyring}): Raw-AES where available, otherwise
 * the hierarchical keyring, the one the native Rust ESDK supports. ESDK-originated failures
 * surface as a modeled {@link ESDKClientError}.
 */
class EncryptionContextBehaviorTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server encryption-context plaintext".getBytes(StandardCharsets.UTF_8);
    private static final String RESERVED_KEY = "aws-crypto-public-key";
    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /**
     * The single keyring both endpoints support (Raw-AES, else hierarchical), gated so the pair is
     * a visible skip when they share none. Resolved before producing a message.
     */
    private static ESDKClientConfig configFor(TargetPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring.config(POLICY);
    }

    /**
     * EC-010: a caller-supplied encryption context containing the reserved
     * {@code aws-crypto-public-key} key must make encrypt fail. Per-server property.
     */
    @ParameterizedTest(name = "reservedEcKeyRejected {0}")
    @MethodSource("targets")
    void encryptRejectsReservedEncryptionContextKey(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        Map<String, String> reserved = new LinkedHashMap<>();
        reserved.put(RESERVED_KEY, "any-value");
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
    void decryptSucceedsWithMatchingReproducedContext(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        Map<String, String> ec = Map.of("purpose", "test", "tenant", "acme");
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, null, null);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, ec);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt with the exact reproduced encryption context must recover the plaintext ("
                + pair + ")");
    }

    /**
     * EC-023: decrypt must fail when the reproduced encryption context mismatches the
     * header — here a present key given a different value. Cross-language matrix.
     */
    @ParameterizedTest(name = "reproducedEcMismatchRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsMismatchedReproducedContext(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        Map<String, String> ec = Map.of("purpose", "test");
        Map<String, String> wrong = Map.of("purpose", "tampered");
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
    void encryptionContextWithHighCodepointsRoundTrips(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        Map<String, String> ec = Map.of(
            "\u65e5\u672c\u8a9e", "value",          // CJK key
            "key-\ud83d\udd11", "\ud83d\ude80");    // astral-plane (emoji) key and value
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, null, null);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, ec);
        assertArrayEquals(PLAINTEXT, recovered,
            "an encryption context with high Unicode code points must round-trip (" + pair + ")");
    }

    /**
     * Encryption-context keys that collide with reserved member names of a language's map/object
     * type round-trip: the message format allows any UTF-8 key
     * ({@code spec/framework/structures.md#encryption-context}), so a decryptor whose context
     * container treats {@code __proto__}, {@code constructor}, or {@code hasOwnProperty} as
     * special rejects or corrupts valid foreign messages. That shipped in the JavaScript ESDK,
     * where a header key matching an inherited {@code Object.prototype} property tripped the
     * duplicate-key check and valid messages failed to decrypt.
     */
    @ParameterizedTest(name = "reservedIdentifierEcKeysRoundTrip {0}")
    @MethodSource("pairs")
    void encryptionContextKeysCollidingWithReservedIdentifiersRoundTrip(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        Map<String, String> ec = Map.of(
            "__proto__", "a",
            "constructor", "b",
            "hasOwnProperty", "c",
            "toString", "d",
            "__init__", "e");
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, null, null);
        if (pair.encryptTarget().language().equals(pair.decryptTarget().language())) {
            // A producer that mishandles a colliding key mishandles it the same way on its
            // own decrypt, so a same-language pair round-trips regardless; only a
            // cross-language decrypt observes the bug, so only those rows are gated.
            assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, ec),
                "encryption-context keys colliding with reserved identifiers must round-trip ("
                    + pair + ")");
            return;
        }
        KnownBugGate.gateDeclared("encrypt-mishandles-proto-encryption-context-key",
            pair.encryptTarget(), () -> {
                byte[] recovered = assertDoesNotThrow(
                    () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext, ec),
                    "decrypt of a message carrying reserved-identifier EC keys (" + pair + ")");
                assertArrayEquals(PLAINTEXT, recovered,
                    "encryption-context keys colliding with reserved identifiers must round-trip ("
                        + pair + ")");
            });
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
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        Map<String, String> reserved = new LinkedHashMap<>();
        reserved.put("aws-crypto-not-a-real-reserved-key", "any-value");
        KnownBugGate.gateDeclared("encrypt-accepts-reserved-prefix-encryption-context-key", target,
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
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        Map<String, String> ec = Map.of("aws-crypto", "no-trailing-hyphen-is-not-reserved");
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, ec, null, null);
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(target.endpoint(), config, ciphertext),
            target + ": a key that does not begin with 'aws-crypto-' must be accepted and round-trip");
    }
}
