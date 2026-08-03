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
 * Raw-keyring behavior conformance. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>KEYRING-003</b> — raw-key decrypt succeeds whenever at least one supplied EDK matches a
 *       held wrapping key: a message wrapped to two keyrings decrypts under a keyring holding only
 *       the second key ({@code spec/framework/raw-aes-keyring.md#ondecrypt}). Asserts only the
 *       decryptor's EDK matching, so it runs decrypt-side
 *       ({@link ReferenceImplementation#decryptSide}); the multi-keyring round trips in
 *       {@code MaterialsRoundTripTests} keep the pairwise producer coverage.</li>
 *   <li><b>KEYRING-053</b> — a multi-keyring with children but no generator cannot create a data
 *       key, so encrypt fails ({@code spec/framework/multi-keyring.md#onencrypt}). Encrypt-time
 *       validation is a per-server property, so it runs against every target.</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). ESDK-originated failures surface as {@link ESDKClientError}.
 */
class RawKeyringBehaviorTests {

    private static final Set<String> FEATURES = Set.of("raw-aes", "multi");

    private static final byte[] PLAINTEXT =
        "esdk-test-server raw-keyring-behavior plaintext".getBytes(StandardCharsets.UTF_8);

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(FEATURES);
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /** KEYRING-003: a two-keyring message decrypts under a keyring holding only the second key. */
    @ParameterizedTest(name = "subsetKeyringDecrypts {0}")
    @MethodSource("decryptSide")
    void decryptSucceedsWithASubsetKeyring(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
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
    @MethodSource("targets")
    void childrenOnlyMultiKeyringCannotEncrypt(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, new EndpointPair(target, target));
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), EsdkClientConfigs.rawAesChildrenOnlyMulti(), PLAINTEXT),
            "a multi-keyring with no generator must fail to encrypt (nothing can create a data key) ("
                + target + ")");
    }
}
