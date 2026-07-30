package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Structural header- and body-field tamper conformance: each test parses the message
 * it produced with {@link EsdkMessage} (whose self-consistency check fails loudly if
 * the layout is misread), corrupts one <em>specific</em> field at its parsed offset,
 * and asserts decrypt rejects it. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>HDR-014</b> — invalid content-type byte rejected
 *       ({@code spec/data-format/message-header.md#content-type}).</li>
 *   <li><b>HDR-020</b> — a header declaring zero EDKs rejected
 *       ({@code spec/data-format/message-header.md#encrypted-data-key-count}).</li>
 *   <li><b>HDR-015</b> — V1 header with a non-zero reserved field rejected
 *       ({@code spec/data-format/message-header.md#reserved}).</li>
 *   <li><b>TAMPER-003</b> — flipped body-frame content byte rejected (AES-GCM tag)
 *       ({@code spec/client-apis/decrypt.md#decrypt-the-message-body}).</li>
 *   <li><b>TAMPER-004</b> — a frame sequence number that breaks the +1 order rejected
 *       ({@code spec/data-format/message-body.md#regular-frame-sequence-number}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). Rejections surface as a modeled {@link ESDKClientError}.
 */
class HeaderFieldTamperTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server structural-tamper plaintext that comfortably spans several small frames"
            .getBytes(StandardCharsets.UTF_8);

    private static final ESDKClientConfig V2_COMMITTING =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    private static final ESDKAlgorithmSuiteId V2_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    private static final ESDKClientConfig V1_SIGNING =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
    private static final ESDKAlgorithmSuiteId V1_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

    /** Small frame length so a modest plaintext yields several frames (for seq/content tampering). */
    private static final long SMALL_FRAME_LENGTH = 16L;

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    private static byte[] encryptV2(EndpointPair pair, long frameLength) {
        return EsdkOps.encrypt(pair.encryptEndpoint(), V2_COMMITTING, PLAINTEXT, Map.of(), V2_SUITE,
            frameLength);
    }

    private static void assertRejected(EndpointPair pair, ESDKClientConfig config, byte[] tampered,
                                       String what) {
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, tampered),
            "decrypt must reject " + what + " (" + pair + ")");
    }

    /** HDR-014: content-type byte set to an unsupported value is rejected. */
    @ParameterizedTest(name = "contentTypeRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsInvalidContentType(EndpointPair pair) {
        byte[] ciphertext = encryptV2(pair, 4096L);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        byte[] tampered = ciphertext.clone();
        tampered[message.contentTypeOffset] = 0x00;
        assertRejected(pair, V2_COMMITTING, tampered, "a message with content-type byte 0x00");
    }

    /** HDR-020: a header declaring zero encrypted data keys is rejected. */
    @ParameterizedTest(name = "edkCountZeroRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsZeroEdkCount(EndpointPair pair) {
        byte[] ciphertext = encryptV2(pair, 4096L);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.edkCount >= 1, "baseline: message must carry at least one EDK");
        byte[] tampered = ciphertext.clone();
        tampered[message.edkCountOffset] = 0x00;
        tampered[message.edkCountOffset + 1] = 0x00;
        assertRejected(pair, V2_COMMITTING, tampered, "a header declaring zero EDKs");
    }

    /** HDR-015: a V1 header whose 4-byte reserved field is non-zero is rejected. */
    @ParameterizedTest(name = "v1ReservedNonZeroRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsNonZeroV1Reserved(EndpointPair pair) {
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), V1_SIGNING, PLAINTEXT, Map.of(),
            V1_SUITE, 4096L);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.reservedOffset > 0, "baseline: V1 message must have a reserved field");
        byte[] tampered = ciphertext.clone();
        tampered[message.reservedOffset] = 0x01;
        assertRejected(pair, V1_SIGNING, tampered, "a V1 header with a non-zero reserved field");
    }

    /** TAMPER-003: flipping a byte of a frame's encrypted content fails the AES-GCM tag. */
    @ParameterizedTest(name = "frameContentTamperRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsTamperedFrameContent(EndpointPair pair) {
        byte[] ciphertext = encryptV2(pair, SMALL_FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        byte[] tampered = ciphertext.clone();
        int contentByte = message.frames.get(0).contentOffset();
        tampered[contentByte] ^= (byte) 0xFF;
        assertRejected(pair, V2_COMMITTING, tampered, "a message with a flipped body-frame content byte");
    }

    /** TAMPER-004: a frame sequence number that breaks the strictly-increasing order is rejected. */
    @ParameterizedTest(name = "frameSequenceTamperRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsTamperedFrameSequenceNumber(EndpointPair pair) {
        byte[] ciphertext = encryptV2(pair, SMALL_FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.frames.size() >= 2,
            "baseline: need at least two frames to tamper the second's sequence number");
        byte[] tampered = ciphertext.clone();
        // Flip the low byte of the second frame's sequence number so it is no longer (previous + 1).
        int seqLowByte = message.frames.get(1).sequenceNumberOffset() + 3;
        tampered[seqLowByte] ^= (byte) 0x01;
        assertRejected(pair, V2_COMMITTING, tampered, "a message with an out-of-order frame sequence number");
    }
}
