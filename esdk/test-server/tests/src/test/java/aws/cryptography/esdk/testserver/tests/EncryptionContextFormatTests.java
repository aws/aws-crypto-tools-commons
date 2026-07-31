package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Encryption-context wire-serialization conformance: assert the header AAD the server
 * produced matches the canonical encryption-context serialization. Per-server structural
 * properties, asserted by parsing the header AAD region. Catalog behaviors
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>EC-031 / HDR-002</b> — an empty encryption context serializes to a 2-byte
 *       zero-length AAD with no key-value-pairs body
 *       ({@code spec/framework/structures.md#serialization}).</li>
 *   <li><b>EC-030 / HDR-003</b> — a non-empty encryption context serializes as a pair count
 *       followed by length-prefixed key/value pairs, keys in ascending unsigned-byte order
 *       ({@code spec/framework/structures.md#serialization}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). Uses a non-signing suite so the header AAD contains exactly the
 * caller's encryption context (a signing suite would add an {@code aws-crypto-public-key}
 * entry).
 */
class EncryptionContextFormatTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server ec-format plaintext".getBytes(StandardCharsets.UTF_8);

    /** Non-signing so the header AAD holds only the caller's context. */
    private static final ESDKClientConfig CONFIG =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    /** EC-031: an empty encryption context serializes to a 2-byte zero length with no body. */
    @ParameterizedTest(name = "emptyEcZeroLength {0}")
    @MethodSource("targets")
    void emptyEncryptionContextSerializesToZeroLength(LanguageServerTarget target) {
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), CONFIG, PLAINTEXT, Map.of(), SUITE, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(0, message.aadLength,
            target + ": an empty encryption context must serialize to a zero-length AAD");
    }

    /**
     * EC-030: the header AAD lists the encryption-context keys in ascending unsigned-byte
     * order, as length-prefixed pairs after a 2-byte pair count.
     */
    @ParameterizedTest(name = "ecKeysCanonicallyOrdered {0}")
    @MethodSource("targets")
    void encryptionContextKeysAreCanonicallyOrdered(LanguageServerTarget target) {
        // Insert keys out of order; the wire form must sort them.
        Map<String, String> ec = new java.util.LinkedHashMap<>();
        ec.put("zebra", "1");
        ec.put("alpha", "2");
        ec.put("mango", "3");
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), CONFIG, PLAINTEXT, ec, SUITE, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.aadLength > 0, target + ": non-empty EC must produce a non-empty AAD");

        int pos = message.aadContentOffset;
        int pairCount = u16(ciphertext, pos);
        pos += 2;
        assertEquals(3, pairCount, target + ": AAD must declare 3 key-value pairs");

        List<String> keys = new ArrayList<>();
        for (int i = 0; i < pairCount; i++) {
            int keyLen = u16(ciphertext, pos);
            pos += 2;
            keys.add(new String(ciphertext, pos, keyLen, StandardCharsets.UTF_8));
            pos += keyLen;
            int valLen = u16(ciphertext, pos);
            pos += 2 + valLen;
        }
        assertEquals(List.of("alpha", "mango", "zebra"), keys,
            target + ": encryption-context keys must be serialized in ascending unsigned-byte order");
    }
}
