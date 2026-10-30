package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmInput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Shared setup for the Default CMM Tests: a Default CMM over a Raw AES keyring
 * with one fixed AES-256 wrapping key, so the encrypt and decrypt targets each
 * build an equivalent CMM, and the two CMM operations.
 */
final class DefaultCmmFixture {

    static final String NAMESPACE = "mpl-test-server";
    static final String KEY_NAME = "default-cmm-key";

    /** The key the Default CMM adds to the context for a signing suite. */
    static final String PUBLIC_KEY_EC_KEY = "aws-crypto-public-key";

    private static final byte[] WRAPPING_KEY = new byte[32];

    static {
        for (int i = 0; i < WRAPPING_KEY.length; i++) WRAPPING_KEY[i] = (byte) (i + 7);
    }

    private DefaultCmmFixture() {
    }

    /** @return the handle of a new Default CMM over the fixed Raw AES keyring. */
    static String createCmm(MPLTestServerClient client) {
        String keyringId = MplTestServerClients.withRetry(() ->
            client.createRawAesKeyring(CreateRawAesKeyringInput.builder()
                .keyNamespace(NAMESPACE)
                .keyName(KEY_NAME)
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())).getKeyringId();
        return MplTestServerClients.withRetry(() ->
            client.createDefaultCmm(CreateDefaultCmmInput.builder()
                .keyringId(keyringId)
                .build())).getCmmId();
    }

    /** @param suite the suite override, or null to let the CMM choose. */
    static GetEncryptionMaterialsInput.Builder getEncryptionMaterials(String cmmId,
            Map<String, String> ec, CommitmentPolicy policy, AlgorithmSuiteId suite) {
        GetEncryptionMaterialsInput.Builder builder = GetEncryptionMaterialsInput.builder()
            .cmmId(cmmId)
            .encryptionContext(ec)
            .commitmentPolicy(policy);
        return suite == null ? builder : builder.algorithmSuiteId(suite);
    }

    static GetEncryptionMaterialsOutput encrypt(MPLTestServerClient client, Map<String, String> ec,
            CommitmentPolicy policy, AlgorithmSuiteId suite) {
        String cmmId = createCmm(client);
        return MplTestServerClients.withRetry(() ->
            client.getEncryptionMaterials(getEncryptionMaterials(cmmId, ec, policy, suite).build()));
    }

    /**
     * @return the DecryptMaterials request for {@code encrypted}, carrying its
     *     suite, EDKs and context as a message header would
     */
    static DecryptMaterialsInput.Builder decryptMaterials(String cmmId,
            GetEncryptionMaterialsOutput encrypted, CommitmentPolicy policy) {
        return DecryptMaterialsInput.builder()
            .cmmId(cmmId)
            .algorithmSuiteId(encrypted.getAlgorithmSuiteId())
            .encryptedDataKeys(encrypted.getEncryptedDataKeys())
            .encryptionContext(encrypted.getEncryptionContext())
            .commitmentPolicy(policy);
    }

    static DecryptMaterialsOutput decrypt(MPLTestServerClient client,
            GetEncryptionMaterialsOutput encrypted, CommitmentPolicy policy) {
        String cmmId = createCmm(client);
        return MplTestServerClients.withRetry(() ->
            client.decryptMaterials(decryptMaterials(cmmId, encrypted, policy).build()));
    }

    /** Copy a ByteBuffer's remaining bytes without moving its position. */
    static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }
}
