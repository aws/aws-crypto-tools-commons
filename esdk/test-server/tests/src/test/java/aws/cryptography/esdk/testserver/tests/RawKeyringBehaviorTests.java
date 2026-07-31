package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Raw-keyring behavior conformance over the cross-language pairwise matrix. Catalog behaviors
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>KEYRING-003</b> — raw-key decrypt succeeds whenever at least one supplied EDK matches a
 *       held wrapping key: a message wrapped to two keyrings decrypts under a keyring holding only
 *       the second key ({@code spec/framework/raw-aes-keyring.md#ondecrypt}).</li>
 *   <li><b>KEYRING-009</b> — an asymmetric RSA keyring built with only the public key can wrap on
 *       encrypt but cannot unwrap on decrypt ({@code spec/framework/raw-rsa-keyring.md#ondecrypt}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES / Raw-RSA). ESDK-originated failures surface as {@link ESDKClientError}.
 */
class RawKeyringBehaviorTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server raw-keyring-behavior plaintext".getBytes(StandardCharsets.UTF_8);

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /** KEYRING-003: a two-keyring message decrypts under a keyring holding only the second key. */
    @ParameterizedTest(name = "subsetKeyringDecrypts {0}")
    @MethodSource("pairs")
    void decryptSucceedsWithASubsetKeyring(EndpointPair pair) {
        FeatureGate.require(Set.of("raw-aes", "multi"), pair);
        // Encrypt to a multi-keyring (generator "a" + child "b") => two EDKs.
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAesMulti(), PLAINTEXT);
        // Decrypt with a keyring holding only key "b" — it matches the second EDK.
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAesBOnly(), ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "a message wrapped to two keyrings must decrypt under a keyring holding only one of the "
                + "matching wrapping keys (" + pair + ")");
    }

    /**
     * KEYRING-053: a multi-keyring with children but no generator cannot create a data key, so
     * encrypt fails (only a generator can generate material).
     */
    @ParameterizedTest(name = "childrenOnlyMultiCannotEncrypt {0}")
    @MethodSource("pairs")
    void childrenOnlyMultiKeyringCannotEncrypt(EndpointPair pair) {
        FeatureGate.require(Set.of("raw-aes", "multi"), pair);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAesChildrenOnlyMulti(), PLAINTEXT),
            "a multi-keyring with no generator must fail to encrypt (nothing can create a data key) ("
                + pair + ")");
    }
}
