package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureGate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Raw-AES encrypted-data-key tamper conformance: the wrapped-key blob is corrupted in place at its
 * parsed offset, and decrypt must reject the message at keyring unwrap — which runs before header
 * authentication, so the rejection is attributable to the keyring, not the header auth tag. Catalog
 * behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>TAMPER-006</b> — a forged/garbage EDK ciphertext blob fails to unwrap
 *       ({@code spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt}). The catalog entry drives
 *       this with a KMS keyring; the offline suite exercises the same "garbage EDK ciphertext fails
 *       to unwrap" behavior with the Raw-AES keyring.</li>
 *   <li><b>HDR-024</b> — a raw-AES wrapped EDK whose embedded structure is malformed — here the
 *       key-provider-info IV length no longer matches the wrapping suite's 12 bytes — is rejected
 *       ({@code spec/framework/raw-aes-keyring.md#ondecrypt}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES / Default CMM). Rejections surface as a modeled {@link ESDKClientError}.
 */
class RawAesEdkTamperTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server raw-aes edk-tamper plaintext".getBytes(StandardCharsets.UTF_8);
    /** The wrapping suite's IV length; the raw-AES key provider info must carry this value. */
    private static final int WRAPPING_IV_LEN = 12;

    /** Byte offsets of the first encrypted data key's provider info and ciphertext blob. */
    private record FirstEdk(int providerInfoOffset, int providerInfoLen, int ciphertextOffset,
                            int ciphertextLen) {
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    private static int u32(byte[] b, int i) {
        return ((b[i] & 0xFF) << 24) | ((b[i + 1] & 0xFF) << 16) | ((b[i + 2] & 0xFF) << 8)
            | (b[i + 3] & 0xFF);
    }

    /** Walk to the first EDK (key provider id, key provider info, ciphertext) from the EDK count. */
    private static FirstEdk firstEdk(EsdkMessage message) {
        byte[] b = message.bytes;
        int pos = message.edkCountOffset + 2;         // skip the 2-byte EDK count
        int providerIdLen = u16(b, pos);
        pos += 2 + providerIdLen;                     // skip the key provider id
        int providerInfoLen = u16(b, pos);
        int providerInfoOffset = pos + 2;
        pos = providerInfoOffset + providerInfoLen;   // skip the key provider info
        int ciphertextLen = u16(b, pos);
        int ciphertextOffset = pos + 2;
        return new FirstEdk(providerInfoOffset, providerInfoLen, ciphertextOffset, ciphertextLen);
    }

    private static byte[] encrypt(TargetPair pair) {
        return EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAes(), PLAINTEXT);
    }

    /**
     * TAMPER-006: replacing the wrapped-key ciphertext blob with garbage makes the raw-AES keyring's
     * unwrap fail.
     */
    @ParameterizedTest(name = "garbledEdkCiphertextRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsGarbledEdkCiphertext(TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        byte[] ciphertext = encrypt(pair);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAes(), ciphertext),
            "baseline: the untampered message must decrypt (" + pair + ")");
        FirstEdk edk = firstEdk(EsdkMessage.parse(ciphertext));
        assertTrue(edk.ciphertextLen() > 0,
            "baseline: the EDK must carry a non-empty ciphertext blob (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        for (int i = 0; i < edk.ciphertextLen(); i++) {
            tampered[edk.ciphertextOffset() + i] ^= (byte) 0xFF;
        }
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAes(), tampered),
            "decrypt must reject a message whose EDK wrapped-key ciphertext is garbage (" + pair + ")");
    }

    /**
     * HDR-024: a key-provider-info IV length that does not match the wrapping suite (11 instead of
     * 12) is rejected.
     */
    @ParameterizedTest(name = "malformedEdkIvLengthRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsMalformedEdkIvLength(TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        byte[] ciphertext = encrypt(pair);
        FirstEdk edk = firstEdk(EsdkMessage.parse(ciphertext));
        // Key provider info = keyName || tagLength(4) || ivLength(4) || IV(ivLength); the 4-byte
        // IV-length field ends 16 bytes (ivLength=12 + the 4-byte field itself) before its end.
        int ivLengthField = edk.providerInfoOffset() + edk.providerInfoLen() - (WRAPPING_IV_LEN + 4);
        assertEquals(WRAPPING_IV_LEN, u32(ciphertext, ivLengthField),
            "baseline: the key provider info must declare a 12-byte IV (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        tampered[ivLengthField] = 0;
        tampered[ivLengthField + 1] = 0;
        tampered[ivLengthField + 2] = 0;
        tampered[ivLengthField + 3] = (byte) (WRAPPING_IV_LEN - 1);  // 11: no longer matches the suite
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAes(), tampered),
            "decrypt must reject a raw-AES EDK whose embedded IV length does not match the suite ("
                + pair + ")");
    }
}
