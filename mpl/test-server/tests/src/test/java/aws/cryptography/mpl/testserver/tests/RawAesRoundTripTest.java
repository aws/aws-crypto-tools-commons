package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import java.util.HashMap;
import java.util.Map;

/**
 * Full MPL round trip across the pairwise matrix:
 * CreateRawAesKeyring → CreateDefaultCmm → GetEncryptionMaterials on the
 * encrypt target → DecryptMaterials on the decrypt target using EDKs from the
 * encrypt side.
 */
@KeyringFeature({"raw-aes", "default-cmm"})
public class RawAesRoundTripTest {

    private static final byte[] WRAPPING_KEY = new byte[32];
    static {
        for (int i = 0; i < WRAPPING_KEY.length; i++) WRAPPING_KEY[i] = (byte) i;
    }

    @KeyringTest(name = "[raw-aes] round-trip {0}", pairs = true)
    void rawAes256RoundTrip(Mpl encryptingMpl, Mpl decryptingMpl) {
        // Create keyring on the encrypt target
        Keyring keyring = roundTripKeyring(encryptingMpl);
        assertNotNull(keyring.id());
        assertFalse(keyring.id().isBlank());

        // Create default CMM on the encrypt target
        Cmm cmm = encryptingMpl.defaultCmm(keyring);
        assertNotNull(cmm.id());

        // GetEncryptionMaterials
        Map<String, String> ec = new HashMap<>();
        ec.put("purpose", "cross-lang-test");

        GetEncryptionMaterialsOutput encMaterials =
            cmm.getEncryptionMaterials(ec, CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT, null);

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
        Cmm decryptingCmm = decryptingMpl.defaultCmm(roundTripKeyring(decryptingMpl));

        // DecryptMaterials on the decrypt target
        DecryptMaterialsOutput decMaterials = decryptingCmm.decryptMaterials(
            encMaterials, CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

        assertNotNull(decMaterials.getPlaintextDataKey());
        // The decrypted PDK must match the one from encryption
        assertEquals(encMaterials.getPlaintextDataKey(), decMaterials.getPlaintextDataKey());
    }

    private static Keyring roundTripKeyring(Mpl mpl) {
        return mpl.rawAesKeyring()
            .keyNamespace("mpl-test-server")
            .keyName("round-trip-key")
            .wrappingKey(WRAPPING_KEY)
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .create();
    }
}
