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
 *       Decrypt-side rows; the decryptor holds the multi's generator keyring alone, so the cap
 *       is exercised on targets without multi-keyring support.</li>
 *   <li><b>HDR-019</b> — header parse enforces the maxEncryptedDataKeys bound: EDK counts at or
 *       below the max are accepted, counts above are rejected
 *       ({@code spec/data-format/message-header.md#encrypted-data-key-count}). Proven by the same
 *       two-EDK message that the DEC-002 case decrypts under a cap of 2 and rejects under a cap of
 *       1.</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES multi-keyring / Default CMM). Rejections surface as a modeled
 * {@link ESDKClientError}.
 */
class MaxEncryptedDataKeysTests {

    /** Producing the two-EDK message needs the multi-keyring. */
    private static final Set<String> FEATURES = Set.of("raw-aes", "multi");
    /** Decrypting it needs only the generator's single raw-AES keyring. */
    private static final Set<String> DECRYPTOR_FEATURES = Set.of("raw-aes");

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
     * DEC-002 / HDR-019: a two-EDK message decrypts under a cap of 2 (count at/below the max
     * accepted) but is rejected under a cap of 1 (count above the max rejected, before any unwrap).
     * Decrypt-side: the reference produces the two-EDK message with the multi-keyring; every
     * raw-AES-capable target decrypts holding the generator keyring alone, so the cap is
     * exercised on targets without multi-keyring support.
     */
    @ParameterizedTest(name = "decryptEnforcesMaxEdks {0}")
    @MethodSource("decryptSide")
    void decryptEnforcesMaxEncryptedDataKeys(ReferencePair pair) {
        FeatureGate.require(FEATURES,
            new EndpointPair(pair.encryptTarget(), pair.encryptTarget()));
        FeatureGate.require(DECRYPTOR_FEATURES,
            new EndpointPair(pair.decryptTarget(), pair.decryptTarget()));
        // Encrypt a two-EDK message with no cap.
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAesMulti(), PLAINTEXT);

        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAesWithMaxEdks(2), ciphertext),
            "a two-EDK message must decrypt under a cap of 2 (" + pair + ")");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAesWithMaxEdks(1), ciphertext),
            "decrypt of a two-EDK message under a max of 1 must be rejected (" + pair + ")");
    }
}
