package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Additional structural tamper conformance, each parsing the produced message with
 * {@link EsdkMessage} and corrupting one specific field. Catalog behaviors
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>TAMPER-005</b> — a final-frame content length greater than the header frame
 *       length is rejected
 *       ({@code spec/client-apis/decrypt.md#decrypt-the-message-body}).</li>
 *   <li><b>FOOT-004</b> — a signed message whose footer is truncated (signature bytes
 *       dropped) is rejected
 *       ({@code spec/client-apis/decrypt.md#verify-the-signature}).</li>
 *   <li><b>HDR-012</b> — a V1 header with an invalid type byte is rejected
 *       ({@code spec/data-format/message-header.md#supported-types}).</li>
 *   <li><b>HDR-016</b> — a V1 header whose IV length does not match the suite is rejected
 *       ({@code spec/data-format/message-header.md#iv-length}).</li>
 *   <li><b>HDR-018</b> — a V1 header carrying a committing (V2) algorithm-suite id is
 *       rejected ({@code spec/data-format/message.md#structure}).</li>
 * </ul>
 *
 * <p>Each behavior asserts only the decryptor's validation, so these run decrypt-side:
 * the reference implementation produces each message and every configured target
 * decrypts it ({@link ReferenceImplementation#decryptSide}). Fully offline (Raw-AES).
 * Rejections surface as a modeled {@link ESDKClientError}.
 */
class AdditionalTamperTests {

    private static final Set<String> FEATURES = Set.of("raw-aes");

    private static final byte[] PLAINTEXT =
        "esdk-test-server additional-tamper plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKClientConfig V2_COMMITTING =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    private static final ESDKAlgorithmSuiteId V2_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    private static final ESDKClientConfig V1_FORBID =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
    private static final ESDKAlgorithmSuiteId V1_SIGNING =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    private static final ESDKAlgorithmSuiteId V1_NON_SIGNING =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    /** A committing (V2) algorithm-suite id, byte pair, to plant in a V1 header. */
    private static final int COMMITTING_SUITE_ID = 0x0478;

    private static final long FRAME_LENGTH = 512L;

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(FEATURES);
    }

    private static void putU32(byte[] b, int offset, long value) {
        b[offset] = (byte) (value >>> 24);
        b[offset + 1] = (byte) (value >>> 16);
        b[offset + 2] = (byte) (value >>> 8);
        b[offset + 3] = (byte) value;
    }

    private static void assertRejected(ReferencePair pair, ESDKClientConfig config, byte[] tampered,
                                       String what) {
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, tampered),
            "decrypt must reject " + what + " (" + pair + ")");
    }

    /** TAMPER-005: a final-frame content length exceeding the frame length is rejected. */
    @ParameterizedTest(name = "finalFrameContentLengthOverflowRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsOverlongFinalFrameContentLength(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        // Short plaintext (< frame length) => a single final frame carrying a content-length field.
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V2_COMMITTING, PLAINTEXT, Map.of(),
            V2_SUITE, FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        EsdkMessage.Frame finalFrame = message.frames.get(message.frames.size() - 1);
        assertTrue(finalFrame.isFinal() && finalFrame.contentLengthOffset() >= 0,
            "baseline: expected a single final frame with a content-length field (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        putU32(tampered, finalFrame.contentLengthOffset(), FRAME_LENGTH + 1);
        assertRejected(pair, V2_COMMITTING, tampered,
            "a final-frame content length greater than the frame length");
    }

    /** FOOT-004: a signed message with its footer signature bytes dropped is rejected. */
    @ParameterizedTest(name = "truncatedFooterRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsTruncatedFooter(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V1_FORBID, PLAINTEXT, Map.of(),
            V1_SIGNING, FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.footerOffset >= 0, "baseline: signing suite must produce a footer (" + pair + ")");
        // Keep the 2-byte signature-length field, drop the signature bytes.
        byte[] tampered = Arrays.copyOf(ciphertext, message.footerOffset + 2);
        assertRejected(pair, V1_FORBID, tampered, "a signed message whose footer signature is truncated");
    }

    /** HDR-012: an unsupported V1 type byte is rejected. */
    @ParameterizedTest(name = "v1InvalidTypeRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsInvalidV1Type(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V1_FORBID, PLAINTEXT, Map.of(),
            V1_NON_SIGNING, FRAME_LENGTH);
        byte[] tampered = ciphertext.clone();
        tampered[1] = 0x00;  // V1 type byte (0x80 = Customer AED) set to an unsupported value
        assertRejected(pair, V1_FORBID, tampered, "a V1 header with an unsupported type byte");
    }

    /** HDR-016: a V1 IV-length field that disagrees with the suite is rejected. */
    @ParameterizedTest(name = "v1IvLengthMismatchRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsV1IvLengthMismatch(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V1_FORBID, PLAINTEXT, Map.of(),
            V1_NON_SIGNING, FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.ivLengthOffset > 0, "baseline: V1 message must carry an IV-length field (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        tampered[message.ivLengthOffset] = 11;  // suite IV length is 12
        assertRejected(pair, V1_FORBID, tampered, "a V1 header whose IV length does not match the suite");
    }

    /** HDR-018: a V1 header carrying a committing (V2) algorithm-suite id is rejected. */
    @ParameterizedTest(name = "v1WithCommittingSuiteIdRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsV1HeaderWithCommittingSuiteId(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V1_FORBID, PLAINTEXT, Map.of(),
            V1_NON_SIGNING, FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        byte[] tampered = ciphertext.clone();
        tampered[message.suiteIdOffset] = (byte) (COMMITTING_SUITE_ID >>> 8);
        tampered[message.suiteIdOffset + 1] = (byte) COMMITTING_SUITE_ID;
        assertRejected(pair, V1_FORBID, tampered,
            "a V1 header (version 1.0) carrying a committing V2 algorithm-suite id");
    }

    /** HDR-017: a framed header whose frame length is 0 (only valid for non-framed) is rejected. */
    @ParameterizedTest(name = "framedZeroFrameLengthRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsFramedHeaderWithZeroFrameLength(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V2_COMMITTING, PLAINTEXT, Map.of(),
            V2_SUITE, FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        byte[] tampered = ciphertext.clone();
        putU32(tampered, message.frameLengthOffset, 0);
        assertRejected(pair, V2_COMMITTING, tampered,
            "a framed header whose frame length is 0");
    }
}
