package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * Verification-key encryption-context conformance (FOOT-006): the reserved
 * {@code aws-crypto-public-key} encryption-context entry must agree with the algorithm suite —
 * a signed suite whose header is missing it is rejected, and an unsigned suite whose header
 * carries a stray one is rejected. The default CMM makes this check while assembling the
 * decryption materials, before the header authentication tag is verified. Catalog behavior
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>FOOT-006</b> — the {@code aws-crypto-public-key} EC entry must agree with the suite
 *       ({@code spec/framework/default-cmm.md#decrypt-materials}).</li>
 * </ul>
 *
 * <p>Both cases edit the header encryption context in place at equal byte length (renaming a key),
 * so the rest of the message stays walkable and the default-CMM suite/EC check is what fires.
 * Fully offline (Raw-AES). Rejections surface as a modeled {@link ESDKClientError}.
 */
class VerificationKeyContextTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server verification-key-context plaintext".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PUBLIC_KEY = "aws-crypto-public-key".getBytes(StandardCharsets.US_ASCII);
    /** A caller EC key of the same byte length as {@code aws-crypto-public-key} (21 bytes). */
    private static final String STRAY_PLACEHOLDER_KEY = "esdk-ts-stray-ec-key1";

    private static final ESDKClientConfig SIGNING_CONFIG =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    private static final ESDKAlgorithmSuiteId SIGNING_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;

    private static final ESDKClientConfig NON_SIGNING_CONFIG =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
    private static final ESDKAlgorithmSuiteId NON_SIGNING_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /** Absolute offset of {@code needle} within the header AAD region, or -1 if absent. */
    private static int aadIndexOf(EsdkMessage message, byte[] needle) {
        int start = message.aadContentOffset;
        int end = start + message.aadLength;
        for (int i = start; i + needle.length <= end; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (message.bytes[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    /** FOOT-006: a signed message whose {@code aws-crypto-public-key} EC key is renamed away (so the
     * verification key is absent) is rejected. */
    @ParameterizedTest(name = "signedMissingVerificationKeyRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsSignedSuiteMissingVerificationKey(EndpointPair pair) {
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), SIGNING_CONFIG, PLAINTEXT, Map.of(),
            SIGNING_SUITE, null);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(pair.decryptEndpoint(), SIGNING_CONFIG, ciphertext),
            "baseline: the untampered signed message must decrypt (" + pair + ")");
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        int keyOffset = aadIndexOf(message, PUBLIC_KEY);
        assertTrue(keyOffset >= 0,
            "baseline: a signing suite must carry an aws-crypto-public-key EC entry (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        tampered[keyOffset] ^= (byte) 0x01;  // rename the key so no aws-crypto-public-key entry remains
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), SIGNING_CONFIG, tampered),
            "decrypt of a signed message missing its verification key must be rejected (" + pair + ")");
    }

    /** FOOT-006: an unsigned message carrying a stray {@code aws-crypto-public-key} EC entry
     * (a caller key renamed to it) is rejected. */
    @ParameterizedTest(name = "unsignedStrayVerificationKeyRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsUnsignedSuiteWithStrayVerificationKey(EndpointPair pair) {
        assertEquals(PUBLIC_KEY.length, STRAY_PLACEHOLDER_KEY.length(),
            "the placeholder EC key must match aws-crypto-public-key's byte length for an in-place rename");
        Map<String, String> ec = Map.of(STRAY_PLACEHOLDER_KEY, "v");
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), NON_SIGNING_CONFIG, PLAINTEXT, ec,
            NON_SIGNING_SUITE, null);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(pair.decryptEndpoint(), NON_SIGNING_CONFIG, ciphertext),
            "baseline: the untampered unsigned message must decrypt (" + pair + ")");
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        int keyOffset = aadIndexOf(message, STRAY_PLACEHOLDER_KEY.getBytes(StandardCharsets.US_ASCII));
        assertTrue(keyOffset >= 0,
            "baseline: the placeholder EC key must be present to rename (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        System.arraycopy(PUBLIC_KEY, 0, tampered, keyOffset, PUBLIC_KEY.length);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), NON_SIGNING_CONFIG, tampered),
            "decrypt of an unsigned message carrying a stray aws-crypto-public-key must be rejected ("
                + pair + ")");
    }
}
