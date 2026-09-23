package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.GenericServerError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Encryption-context serialized-size boundary at the header's 2-byte AAD length field
 * ({@code spec/data-format/message-header.md#aad-length}). The serialized key-value pairs
 * structure ({@code spec/data-format/message-header.md#aad}) is
 * {@code count(2) || [keyLen(2) || key || valLen(2) || value]...}, so with a 1-byte key the
 * largest representable value is 65528 bytes (7 + 65528 = 65535 = UInt16 max).
 *
 * <ul>
 *   <li>An encryption context that serializes to exactly 65535 bytes is representable, so it
 *       must encrypt, carry the exact AAD length on the wire, and round-trip cross-language
 *       with the full context authenticated.</li>
 *   <li>One byte more is unrepresentable in the message format: no conformant message can be
 *       emitted, so encrypt must fail closed — silently truncating or wrapping the length
 *       would emit a corrupt or wrongly-authenticated message.</li>
 * </ul>
 *
 * <p>Uses a committing, non-signing suite (0x0478) so the default CMM adds no
 * {@code aws-crypto-public-key} entry and the serialized size is exactly the caller's context.
 * The AAD-length boundary is keyring-independent, so each combination runs once under the keyring
 * both endpoints support ({@link ConformanceKeyring}): Raw-AES where available, otherwise the
 * hierarchical keyring, the one the native Rust ESDK supports.
 */
class EncryptionContextSizeBoundaryTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server ec-size-boundary plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    private static final ESDKAlgorithmSuiteId NON_SIGNING_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    /** Serialized AAD bytes for a single-entry context with a 1-byte key: 7 + valueLength. */
    private static final int SINGLE_ENTRY_OVERHEAD = 7;
    private static final int MAX_AAD = 65535;

    private static final String VALUE_LENGTH_CAP_BUG =
        "encryption-context-value-length-capped-at-32767";

    private static String asciiValue(int length) {
        return "a".repeat(length);
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
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
     * An encryption context serializing to exactly the UInt16 AAD maximum (65535 bytes) is
     * representable: encrypt succeeds, the wire AAD length is exactly 65535, and the message
     * round-trips cross-language. Gated per side on the ledgered java value-length cap
     * (a signed-16-bit bound over an unsigned wire field), which breaks encrypt and decrypt
     * independently.
     */
    @ParameterizedTest(name = "maxSizeEncryptionContextRoundTrips {0}")
    @MethodSource("pairs")
    void maxSizeEncryptionContextRoundTrips(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        Map<String, String> ec = Map.of("k", asciiValue(MAX_AAD - SINGLE_ENTRY_OVERHEAD));

        KnownBugGate.gateDeclared(VALUE_LENGTH_CAP_BUG, pair.encryptTarget(), () -> {
            byte[] ciphertext = assertDoesNotThrow(
                () -> EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, NON_SIGNING_SUITE, null),
                pair + ": encrypt with a maximum-size encryption context must be accepted");
            EsdkMessage message = EsdkMessage.parse(ciphertext);
            assertEquals(MAX_AAD, message.aadLength,
                pair + ": a context serializing to the UInt16 maximum must carry AAD length 65535");

            KnownBugGate.gateDeclared(VALUE_LENGTH_CAP_BUG, pair.decryptTarget(), () -> {
                byte[] recovered = assertDoesNotThrow(
                    () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
                    pair + ": decrypt of a maximum-size encryption context must be accepted");
                assertArrayEquals(PLAINTEXT, recovered,
                    pair + ": a maximum-size encryption context must round-trip");
            });
        });
    }

    /**
     * An encryption context one byte past the UInt16 AAD maximum is unrepresentable in the
     * message format, so encrypt must fail closed rather than emit a truncated or
     * wrongly-lengthed header. The rejection may surface as either modeled error depending on
     * where the server's serializer fails.
     */
    @ParameterizedTest(name = "oversizeEncryptionContextRejected {0}")
    @MethodSource("targets")
    void oversizeEncryptionContextRejected(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        Map<String, String> ec = Map.of("k", asciiValue(MAX_AAD - SINGLE_ENTRY_OVERHEAD + 1));

        try {
            EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, ec, NON_SIGNING_SUITE, null);
            fail(target + ": encrypt must reject an encryption context whose serialization "
                + "exceeds the UInt16 AAD length field");
        } catch (ESDKClientError | GenericServerError expected) {
            // Fail-closed on an unrepresentable context, through either modeled error.
        }
    }
}
