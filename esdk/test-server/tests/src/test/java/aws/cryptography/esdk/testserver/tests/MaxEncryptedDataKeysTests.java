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
 * Maximum-encrypted-data-keys enforcement across the configured Language_Server targets.
 * A two-keyring multi-keyring produces two EDKs, so a cap of 1 must be rejected and a cap of
 * 2 accepted. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>ENC-014</b> — encrypt rejects producing more EDKs than the configured maximum
 *       ({@code spec/client-apis/client.md#maximum-number-of-encrypted-data-keys}). Per-server
 *       property.</li>
 *   <li><b>DEC-002</b> — decrypt rejects a header carrying more EDKs than the configured
 *       maximum before unwrapping ({@code spec/client-apis/decrypt.md#v2-header-deserialization}).
 *       Cross-language matrix.</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES multi-keyring / Default CMM). Rejections surface as a modeled
 * {@link ESDKClientError}.
 */
class MaxEncryptedDataKeysTests {

    private static final Set<String> FEATURES = Set.of("raw-aes", "multi");

    private static final byte[] PLAINTEXT =
        "esdk-test-server max-edk plaintext".getBytes(StandardCharsets.UTF_8);

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(FEATURES);
    }

    /** ENC-014: encrypt with a two-EDK keyring succeeds at a cap of 2 but is rejected at a cap of 1. */
    @ParameterizedTest(name = "encryptEnforcesMaxEdks {0}")
    @MethodSource("targets")
    void encryptEnforcesMaxEncryptedDataKeys(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, new EndpointPair(target, target));
        // Cap of 2 permits the two EDKs.
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(),
            EsdkClientConfigs.rawAesMultiWithMaxEdks(2), PLAINTEXT);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(target.endpoint(), EsdkClientConfigs.rawAesMulti(), ciphertext),
            "a two-EDK message under a cap of 2 must round-trip (" + target + ")");
        // Cap of 1 forbids the second EDK.
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), EsdkClientConfigs.rawAesMultiWithMaxEdks(1), PLAINTEXT),
            "encrypt producing two EDKs under a max of 1 must be rejected (" + target + ")");
    }

    /**
     * DEC-002: a two-EDK message decrypts under a cap of 2 but is rejected under a cap of 1
     * (before any unwrap). Decrypt-side: the reference produces the two-EDK message and
     * every configured target decrypts it.
     */
    @ParameterizedTest(name = "decryptEnforcesMaxEdks {0}")
    @MethodSource("decryptSide")
    void decryptEnforcesMaxEncryptedDataKeys(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        // Encrypt a two-EDK message with no cap.
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAesMulti(), PLAINTEXT);

        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAesMultiWithMaxEdks(2), ciphertext),
            "a two-EDK message must decrypt under a cap of 2 (" + pair + ")");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAesMultiWithMaxEdks(1), ciphertext),
            "decrypt of a two-EDK message under a max of 1 must be rejected (" + pair + ")");
    }
}
