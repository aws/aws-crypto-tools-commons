package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Single-bit-flip tamper conformance (TAMPER-008): flipping any single bit of a valid message
 * makes decrypt fail with no plaintext released. Catalog behavior (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>TAMPER-008</b> — decrypt fails for any single flipped bit of a known-answer vector
 *       ({@code spec/client-apis/decrypt.md#authenticated-data}).</li>
 * </ul>
 *
 * <p>The catalog behavior is the <em>exhaustive</em> single-bit-flip corpus — every bit of the
 * message flipped in turn. This test does not flip every bit; it samples a fixed,
 * deterministically-chosen set of bit positions spread across the whole message, which keeps the
 * cross-language matrix bounded while still exercising each region. A committing signing suite is
 * used so the header (commitment value + authentication tag), body (per-frame tags), and footer
 * (signature) are all integrity-protected, so a flipped bit anywhere in the message is caught.
 *
 * <p>Fully offline (Raw-AES). Rejections surface as a modeled {@link ESDKClientError}.
 */
class BitFlipCorpusTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server bit-flip corpus plaintext, long enough to span more than one body frame"
            .getBytes(StandardCharsets.UTF_8);
    private static final ESDKClientConfig CONFIG =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    private static final long FRAME_LENGTH = 512L;
    /** Number of distinct bit positions sampled per message (not the exhaustive corpus). */
    private static final int SAMPLES = 12;

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /**
     * TAMPER-008: the untampered message decrypts, but flipping any one of a sampled set of bit
     * positions makes decrypt fail.
     */
    @ParameterizedTest(name = "singleBitFlipRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsAnySingleBitFlip(EndpointPair pair) {
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), CONFIG, PLAINTEXT, Map.of(), SUITE,
            FRAME_LENGTH);
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), CONFIG, ciphertext),
            "baseline: the untampered message must decrypt, so each rejection below is the flip ("
                + pair + ")");

        // Fixed seed: the sampled positions are the same on every run, so a failure is reproducible.
        Random random = new Random(0x7A4908L);
        int totalBits = ciphertext.length * 8;
        for (int i = 0; i < SAMPLES; i++) {
            int bit = random.nextInt(totalBits);
            byte[] tampered = ciphertext.clone();
            tampered[bit >> 3] ^= (byte) (1 << (bit & 7));
            assertThrows(ESDKClientError.class,
                () -> EsdkOps.decrypt(pair.decryptEndpoint(), CONFIG, tampered),
                "decrypt must reject the message with bit " + bit + " flipped (" + pair + ")");
        }
    }
}
