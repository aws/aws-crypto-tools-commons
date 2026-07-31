package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Required-Encryption-Context CMM conformance over the cross-language pairwise matrix. The CMM
 * drops the required keys from the header on encrypt and demands them, reproduced, on decrypt.
 * Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>CMM-007</b> — round-trips when the required keys are reproduced exactly on decrypt
 *       ({@code spec/framework/required-encryption-context-cmm.md#decrypt-materials}).</li>
 *   <li><b>CMM-008</b> — decrypt fails when the required keys are not correctly reproduced: none
 *       supplied, the required key missing, or a required key given a wrong value
 *       ({@code spec/framework/required-encryption-context-cmm.md#decrypt-materials}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). The required keys never appear on the wire, so decrypt must obtain
 * them from the reproduced context. ESDK-originated failures surface as {@link ESDKClientError}.
 */
class RequiredEncryptionContextCmmTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server required-ec plaintext".getBytes(StandardCharsets.UTF_8);
    private static final List<String> REQUIRED_KEYS = List.of("purpose", "tenant");
    private static final Map<String, String> FULL_CONTEXT =
        Map.of("purpose", "test", "tenant", "acme");

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    private static ESDKClientConfig config() {
        return EsdkClientConfigs.rawAesRequiredEc(REQUIRED_KEYS);
    }

    /** Encrypt with the required-EC CMM and the full context (required keys dropped from the header). */
    private static byte[] encrypt(EndpointPair pair) {
        FeatureGate.require(Set.of("required-encryption-context", "raw-aes"), pair);
        return EsdkOps.encrypt(pair.encryptEndpoint(), config(), PLAINTEXT, FULL_CONTEXT, null, null);
    }

    /** CMM-007: reproducing the required context exactly on decrypt round-trips. */
    @ParameterizedTest(name = "reproducedRequiredEcDecrypts {0}")
    @MethodSource("pairs")
    void decryptSucceedsWhenRequiredContextReproduced(EndpointPair pair) {
        byte[] ciphertext = encrypt(pair);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, FULL_CONTEXT);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt with the required keys reproduced exactly must recover the plaintext (" + pair + ")");
    }

    /** CMM-008: decrypt with NO reproduced context fails (the required keys are not on the wire). */
    @ParameterizedTest(name = "missingReproducedEcRejected {0}")
    @MethodSource("pairs")
    void decryptFailsWhenNoContextReproduced(EndpointPair pair) {
        byte[] ciphertext = encrypt(pair);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext),
            "decrypt without reproducing the required encryption context must fail (" + pair + ")");
    }

    /** CMM-008: decrypt reproducing only some of the required keys fails. */
    @ParameterizedTest(name = "partialReproducedEcRejected {0}")
    @MethodSource("pairs")
    void decryptFailsWhenRequiredKeyMissing(EndpointPair pair) {
        byte[] ciphertext = encrypt(pair);
        Map<String, String> partial = Map.of("purpose", "test");  // missing "tenant"
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, partial),
            "decrypt missing a required reproduced key must fail (" + pair + ")");
    }

    /** CMM-008: decrypt reproducing a required key with the wrong value fails. */
    @ParameterizedTest(name = "wrongReproducedEcValueRejected {0}")
    @MethodSource("pairs")
    void decryptFailsWhenRequiredValueWrong(EndpointPair pair) {
        byte[] ciphertext = encrypt(pair);
        Map<String, String> wrong = Map.of("purpose", "test", "tenant", "WRONG");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, wrong),
            "decrypt reproducing a required key with a wrong value must fail (" + pair + ")");
    }
}
