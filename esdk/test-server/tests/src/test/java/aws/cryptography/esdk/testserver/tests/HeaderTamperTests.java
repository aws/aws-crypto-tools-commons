package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Header- and footer-tamper conformance driven off <em>fixed</em> message offsets
 * (no full wire-format parse needed): the message version byte, the algorithm-suite
 * id, a message-id byte, and the final byte all sit at positions determined solely
 * by the message-format version, so each can be corrupted directly on the ciphertext
 * bytes the test holds. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>HDR-011</b> — decrypt rejects an unsupported version byte
 *       ({@code spec/client-apis/decrypt.md#parse-the-header}).</li>
 *   <li><b>HDR-013</b> — decrypt rejects an unknown algorithm-suite id
 *       ({@code spec/data-format/message-header.md#algorithm-suite-id}).</li>
 *   <li><b>TAMPER-001</b> — decrypt rejects any flipped byte in the authenticated
 *       header; here a message-id byte
 *       ({@code spec/client-apis/decrypt.md#verify-the-header}).</li>
 *   <li><b>FOOT-003 / TAMPER-003</b> — corrupting the final byte rejects the message:
 *       for a signing suite the last byte is the footer signature (FOOT-003,
 *       {@code spec/client-apis/decrypt.md#verify-the-signature}); for a non-signing
 *       suite it is the final-frame auth tag (TAMPER-003,
 *       {@code spec/client-apis/decrypt.md#decrypt-the-message-body}).</li>
 * </ul>
 *
 * <p>Run over the cross-language pairwise matrix and both message-format layouts (a
 * V2 committing suite and a V1 non-committing signing suite), so the version-specific
 * header offsets are covered. Fully offline (Raw-AES). Every rejection is asserted to
 * surface as a modeled {@link ESDKClientError}.
 */
class HeaderTamperTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server header-tamper plaintext".getBytes(StandardCharsets.UTF_8);

    /**
     * A message-format layout under test: which commitment policy + suite to encrypt
     * with, the expected version byte, the 2-byte algorithm-suite-id offset, one
     * in-range message-id byte offset, and whether the suite signs (so the final byte
     * is a signature rather than a frame auth tag).
     *
     * <p>V1 header body starts: version(1) type(1) suiteId(2) messageId(16)...
     * V2 header body starts: version(1) suiteId(2) messageId(32)...
     */
    record Layout(String label, ESDKClientConfig config, ESDKAlgorithmSuiteId suite,
                  byte versionByte, int suiteIdOffset, int messageIdByteOffset, boolean signed) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final Layout V2_COMMITTING = new Layout(
        "v2-committing",
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT),
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        (byte) 0x02, 1, 3, false);

    private static final Layout V1_SIGNING = new Layout(
        "v1-signing",
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT),
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA384_ECDSA_P384,
        (byte) 0x01, 2, 4, true);

    private static final List<Layout> LAYOUTS = List.of(V2_COMMITTING, V1_SIGNING);

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (EndpointPair pair : LanguageServerRegistry.shared().pairs()) {
            for (Layout layout : LAYOUTS) {
                cases.add(Arguments.of(pair, layout));
            }
        }
        return cases;
    }

    /** Encrypt one message for {@code layout} on the pair's encrypt endpoint. */
    private static byte[] encrypt(EndpointPair pair, Layout layout) {
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), layout.config(), PLAINTEXT,
            Map.of(), layout.suite(), null);
        // Sanity: the layout's expected version byte is what the server produced.
        if (ciphertext[0] != layout.versionByte()) {
            throw new IllegalStateException("expected version byte " + layout.versionByte()
                + " for " + layout.label() + " but got " + ciphertext[0]);
        }
        return ciphertext;
    }

    /** HDR-011: an unsupported version byte is rejected. */
    @ParameterizedTest(name = "versionByteRejected[{1}] {0}")
    @MethodSource("cases")
    void decryptRejectsUnsupportedVersionByte(EndpointPair pair, Layout layout) {
        byte[] ciphertext = encrypt(pair, layout);
        assertBaselineDecrypts(pair, layout, ciphertext);

        byte[] tampered = ciphertext.clone();
        tampered[0] = (byte) 0xFF;
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), layout.config(), tampered),
            "decrypt of a message with an unsupported version byte must be rejected ("
                + pair + ", " + layout + ")");
    }

    /** HDR-013: an unknown algorithm-suite id is rejected. */
    @ParameterizedTest(name = "suiteIdRejected[{1}] {0}")
    @MethodSource("cases")
    void decryptRejectsUnknownSuiteId(EndpointPair pair, Layout layout) {
        byte[] ciphertext = encrypt(pair, layout);
        byte[] tampered = ciphertext.clone();
        tampered[layout.suiteIdOffset()] = (byte) 0xFF;
        tampered[layout.suiteIdOffset() + 1] = (byte) 0xFF;
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), layout.config(), tampered),
            "decrypt of a message whose algorithm-suite id is unknown must be rejected ("
                + pair + ", " + layout + ")");
    }

    /** TAMPER-001: flipping an authenticated header byte (a message-id byte) is rejected. */
    @ParameterizedTest(name = "headerByteTamperRejected[{1}] {0}")
    @MethodSource("cases")
    void decryptRejectsTamperedHeaderByte(EndpointPair pair, Layout layout) {
        byte[] ciphertext = encrypt(pair, layout);
        byte[] tampered = ciphertext.clone();
        tampered[layout.messageIdByteOffset()] ^= (byte) 0xFF;
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), layout.config(), tampered),
            "decrypt of a message with a flipped message-id (authenticated header) byte must be "
                + "rejected (" + pair + ", " + layout + ")");
    }

    /**
     * FOOT-003 / TAMPER-003: corrupting the final byte is rejected — the footer
     * signature for a signing suite, the final-frame auth tag otherwise.
     */
    @ParameterizedTest(name = "finalByteTamperRejected[{1}] {0}")
    @MethodSource("cases")
    void decryptRejectsTamperedFinalByte(EndpointPair pair, Layout layout) {
        byte[] ciphertext = encrypt(pair, layout);
        byte[] tampered = ciphertext.clone();
        tampered[tampered.length - 1] ^= (byte) 0xFF;
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), layout.config(), tampered),
            "decrypt of a message whose final byte (" + (layout.signed() ? "footer signature"
                : "final-frame auth tag") + ") is corrupted must be rejected (" + pair + ", "
                + layout + ")");
    }

    private static void assertBaselineDecrypts(EndpointPair pair, Layout layout, byte[] ciphertext) {
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), layout.config(), ciphertext),
            "baseline: the untampered message must decrypt (" + pair + ", " + layout + ")");
    }
}
