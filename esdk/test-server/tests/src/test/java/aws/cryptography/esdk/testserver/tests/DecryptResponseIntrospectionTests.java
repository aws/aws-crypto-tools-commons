package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.DecryptOutput;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Asserts what the decryptor exposes on its response: the authenticated encryption context and
 * the algorithm suite it determined from the message header. A Language_Server that does not
 * surface its decrypt result leaves those fields null, in which case each test reports as skipped
 * (via {@link Assumptions}) rather than passing vacuously — so the report shows exactly which
 * servers expose decrypt introspection.
 */
class DecryptResponseIntrospectionTests {

    private static final byte[] PLAINTEXT =
        "decrypt-response introspection".getBytes(StandardCharsets.UTF_8);

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /**
     * EC-003: the decrypt response exposes the algorithm suite the message used and the
     * authenticated encryption context. Cross-language matrix.
     */
    @ParameterizedTest(name = "decryptResponseExposesSuiteAndContext {0}")
    @MethodSource("pairs")
    void decryptResponseExposesSuiteAndContext(EndpointPair pair) {
        Map<String, String> ec = Map.of("purpose", "introspection");
        ESDKAlgorithmSuiteId suite = ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, suite, null);
        DecryptOutput response =
            EsdkOps.decryptResponse(pair.decryptEndpoint(), config, ciphertext, Map.of());

        Assumptions.assumeTrue(response.getAlgorithmSuiteId() != null,
            "decryptor does not expose the algorithm suite id (" + pair + ")");
        assertEquals(suite, response.getAlgorithmSuiteId(),
            "decrypt response must expose the algorithm suite the message used (" + pair + ")");
        assertEquals("introspection", response.getEncryptionContext().get("purpose"),
            "decrypt response must expose the authenticated encryption context (" + pair + ")");
    }

    /**
     * EC-012/013: under a signing suite the default CMM adds the reserved signature public key
     * ({@code aws-crypto-public-key}) to the encryption context, and the decryptor exposes it
     * alongside the caller's own context entries. Cross-language matrix.
     */
    @ParameterizedTest(name = "decryptResponseExposesSignaturePublicKey {0}")
    @MethodSource("pairs")
    void decryptResponseExposesSignaturePublicKey(EndpointPair pair) {
        Map<String, String> ec = Map.of("purpose", "signing");
        ESDKAlgorithmSuiteId suite =
            ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, ec, suite, null);
        DecryptOutput response =
            EsdkOps.decryptResponse(pair.decryptEndpoint(), config, ciphertext, Map.of());

        Assumptions.assumeTrue(
            response.getEncryptionContext() != null && !response.getEncryptionContext().isEmpty(),
            "decryptor does not expose the encryption context (" + pair + ")");
        assertTrue(response.getEncryptionContext().containsKey("aws-crypto-public-key"),
            "a signing suite's decrypt response must expose the reserved signature public key in the "
                + "encryption context (" + pair + ")");
        assertEquals("signing", response.getEncryptionContext().get("purpose"),
            "decrypt response must also expose the caller's encryption context (" + pair + ")");
    }
}
