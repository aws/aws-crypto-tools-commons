package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
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
 * Synthetic malformed-header conformance: encrypt a real message, then rewrite the
 * encryption-context region with {@link EsdkHeaderEditor} to make it structurally invalid,
 * and assert decrypt rejects it. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>HDR-021</b> — a header with a bad key-value-pairs count or key-length field
 *       (inflated past the AAD, or zero) is rejected
 *       ({@code spec/data-format/message-header.md#aad}).</li>
 *   <li><b>HDR-022</b> — a header whose encryption context contains duplicate keys is rejected
 *       ({@code spec/framework/structures.md#serialization}).</li>
 * </ul>
 *
 * <p>Each edit is to the encryption-context/EDK-count region, not the keyring's EDK, so each pair
 * runs once under the keyring both endpoints support ({@link ConformanceKeyring}: Raw-AES where
 * available, else the hierarchical keyring the native Rust ESDK supports). A non-signing suite is
 * used so the header AAD holds exactly the caller's encryption context. Rejections surface as a
 * modeled {@link ESDKClientError}.
 */
class SyntheticHeaderTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server synthetic-header plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    /** Two encryption-context pairs whose keys serialize to equal byte lengths (for the duplicate-key edit). */
    private static Map<String, String> twoPairContext() {
        Map<String, String> ec = new LinkedHashMap<>();
        ec.put("aa", "11");
        ec.put("bb", "22");
        return ec;
    }

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    private static ESDKClientConfig configFor(EndpointPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring.config(POLICY);
    }

    private static EsdkMessage encryptAndParse(EndpointPair pair, ESDKClientConfig config,
                                               Map<String, String> ec) {
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, SUITE, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.aadLength > 0, "baseline: the message must carry a non-empty encryption context (" + pair + ")");
        return message;
    }

    private static void assertRejected(EndpointPair pair, ESDKClientConfig config, byte[] tampered,
                                       String what) {
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, tampered),
            "decrypt must reject " + what + " (" + pair + ")");
    }

    /** HDR-021: an encryption-context pair count inflated far beyond the bytes present is rejected. */
    @ParameterizedTest(name = "inflatedPairCountRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsInflatedPairCount(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        EsdkMessage message = encryptAndParse(pair, config, twoPairContext());
        assertRejected(pair, config, EsdkHeaderEditor.withPairCount(message, 0xFFFF),
            "a header whose encryption-context pair count (0xFFFF) exceeds the bytes present");
    }

    /** HDR-021: a key-length field inflated past the AAD region is rejected. */
    @ParameterizedTest(name = "inflatedKeyLengthRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsInflatedKeyLength(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        EsdkMessage message = encryptAndParse(pair, config, twoPairContext());
        assertRejected(pair, config, EsdkHeaderEditor.withFirstKeyLength(message, 0xFFFF),
            "a header whose encryption-context key length (0xFFFF) overruns the AAD");
    }

    /** HDR-021: a zero-length encryption-context key is rejected. */
    @ParameterizedTest(name = "zeroKeyLengthRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsZeroKeyLength(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        EsdkMessage message = encryptAndParse(pair, config, twoPairContext());
        assertRejected(pair, config, EsdkHeaderEditor.withFirstKeyLength(message, 0),
            "a header with a zero-length encryption-context key");
    }

    /** HDR-022: a header whose encryption context contains duplicate keys is rejected. */
    @ParameterizedTest(name = "duplicateEcKeyRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsDuplicateEncryptionContextKey(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        EsdkMessage message = encryptAndParse(pair, config, twoPairContext());
        assertRejected(pair, config, EsdkHeaderEditor.withDuplicateFirstKey(message),
            "a header whose encryption context contains a duplicate key");
    }

    /** HDR-023: a header whose encryption-context key is not valid UTF-8 is rejected. */
    @ParameterizedTest(name = "nonUtf8EcKeyRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsNonUtf8EncryptionContextKey(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        EsdkMessage message = encryptAndParse(pair, config, twoPairContext());
        // 0xFF is never a valid UTF-8 byte, so the first key is no longer valid UTF-8.
        assertRejected(pair, config, EsdkHeaderEditor.withFirstKeyByte(message, 0xFF),
            "a header whose encryption-context key is not valid UTF-8");
    }

    /**
     * An encrypted-data-key count inflated far beyond the EDKs present (0xFFFF) makes the header
     * parser walk the following bytes as garbage EDK structures and must be rejected — the EDK-count
     * sibling of the inflated EC pair count above. Added by gap analysis (HDR-020 covers only the
     * zero-count case); not a catalog behavior.
     */
    @ParameterizedTest(name = "inflatedEdkCountRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsInflatedEdkCount(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        EsdkMessage message = encryptAndParse(pair, config, twoPairContext());
        byte[] tampered = message.bytes.clone();
        tampered[message.edkCountOffset] = (byte) 0xFF;
        tampered[message.edkCountOffset + 1] = (byte) 0xFF;
        assertRejected(pair, config, tampered,
            "a header whose encrypted-data-key count (0xFFFF) exceeds the EDKs present");
    }
}
