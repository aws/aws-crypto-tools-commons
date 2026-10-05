package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmInput;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmOutput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringOutput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Full MPL round trip across the pairwise matrix:
 * CreateRawAesKeyring → CreateDefaultCmm → GetEncryptionMaterials on the
 * encrypt target → DecryptMaterials on the decrypt target using EDKs from the
 * encrypt side.
 */
public class RawAesRoundTripTest {

    private static final byte[] WRAPPING_KEY = new byte[32];
    static {
        for (int i = 0; i < WRAPPING_KEY.length; i++) WRAPPING_KEY[i] = (byte) i;
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    @ParameterizedTest(name = "[raw-aes] round-trip {0}")
    @MethodSource("pairs")
    void rawAes256RoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes", "default-cmm"), pair);
        MPLTestServerClient encServer = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient decServer = MplTestServerClients.forEndpoint(pair.decryptEndpoint());

        // Create keyring on the encrypt target
        CreateRawAesKeyringOutput keyringOut = MplTestServerClients.withRetry(() ->
            encServer.createRawAesKeyring(CreateRawAesKeyringInput.builder()
                .keyNamespace("mpl-test-server")
                .keyName("round-trip-key")
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build()));
        assertNotNull(keyringOut.getKeyringId());
        assertFalse(keyringOut.getKeyringId().isBlank());

        // Create default CMM on the encrypt target
        CreateDefaultCmmOutput cmmOut = MplTestServerClients.withRetry(() ->
            encServer.createDefaultCmm(CreateDefaultCmmInput.builder()
                .keyringId(keyringOut.getKeyringId())
                .build()));
        assertNotNull(cmmOut.getCmmId());

        // GetEncryptionMaterials
        Map<String, String> ec = new HashMap<>();
        ec.put("purpose", "cross-lang-test");

        GetEncryptionMaterialsOutput encMaterials = MplTestServerClients.withRetry(() ->
            encServer.getEncryptionMaterials(GetEncryptionMaterialsInput.builder()
                .cmmId(cmmOut.getCmmId())
                .encryptionContext(ec)
                .commitmentPolicy(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build()));

        assertNotNull(encMaterials.getPlaintextDataKey());
        assertTrue(encMaterials.getPlaintextDataKey().remaining() > 0);
        assertNotNull(encMaterials.getEncryptedDataKeys());
        assertFalse(encMaterials.getEncryptedDataKeys().isEmpty());
        // With no suite requested, the Default CMM picks the commitment policy's
        // default: REQUIRE_ENCRYPT_REQUIRE_DECRYPT -> the committing ECDSA P-384 suite,
        // which signs, so the materials carry a signing key.
        assertEquals(AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.getValue(),
            encMaterials.getAlgorithmSuiteId().getValue());
        assertNotNull(encMaterials.getSigningKey());
        assertTrue(encMaterials.getEncryptionContext().containsKey("aws-crypto-public-key"),
            "a signing suite adds the verification key to the encryption context");

        // Create keyring + CMM on the decrypt target (same key)
        CreateRawAesKeyringOutput decKeyringOut = MplTestServerClients.withRetry(() ->
            decServer.createRawAesKeyring(CreateRawAesKeyringInput.builder()
                .keyNamespace("mpl-test-server")
                .keyName("round-trip-key")
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build()));

        CreateDefaultCmmOutput decCmmOut = MplTestServerClients.withRetry(() ->
            decServer.createDefaultCmm(CreateDefaultCmmInput.builder()
                .keyringId(decKeyringOut.getKeyringId())
                .build()));

        // DecryptMaterials on the decrypt target
        DecryptMaterialsOutput decMaterials = MplTestServerClients.withRetry(() ->
            decServer.decryptMaterials(DecryptMaterialsInput.builder()
                .cmmId(decCmmOut.getCmmId())
                .algorithmSuiteId(encMaterials.getAlgorithmSuiteId())
                .encryptedDataKeys(encMaterials.getEncryptedDataKeys())
                .encryptionContext(encMaterials.getEncryptionContext())
                .commitmentPolicy(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build()));

        assertNotNull(decMaterials.getPlaintextDataKey());
        // The decrypted PDK must match the one from encryption
        assertEquals(encMaterials.getPlaintextDataKey(), decMaterials.getPlaintextDataKey());
    }
}
