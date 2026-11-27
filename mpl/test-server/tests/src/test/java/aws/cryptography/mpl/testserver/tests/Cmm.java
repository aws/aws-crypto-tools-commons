package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import java.util.Map;

/**
 * A Default CMM that a language's MPL created, and the two CMM calls.
 *
 * <p>The CMM lives in that language's test server.
 * This object holds only the ID that the test server gave it, and sends each call to the same {@link Mpl}.
 * {@link Mpl#defaultCmm()} builds one over a Raw AES keyring with one fixed AES-256 wrapping key.
 * So the CMMs that two languages build that way can decrypt each other's encrypted data keys.
 */
final class Cmm {

    static final String NAMESPACE = "mpl-test-server";
    static final String KEY_NAME = "default-cmm-key";

    /** The key the Default CMM adds to the context for a signing suite. */
    static final String PUBLIC_KEY_EC_KEY = "aws-crypto-public-key";

    static final byte[] WRAPPING_KEY = new byte[32];

    static {
        for (int i = 0; i < WRAPPING_KEY.length; i++) WRAPPING_KEY[i] = (byte) (i + 7);
    }

    private final Mpl mpl;
    private final String cmmId;

    Cmm(Mpl mpl, String cmmId) {
        this.mpl = mpl;
        this.cmmId = cmmId;
    }

    /** The ID that the test server gave this CMM. */
    String id() {
        return cmmId;
    }

    /** GetEncryptionMaterials, which must succeed. A null {@code suite} lets the CMM choose. */
    GetEncryptionMaterialsOutput getEncryptionMaterials(Map<String, String> encryptionContext,
            CommitmentPolicy policy, AlgorithmSuiteId suite) {
        GetEncryptionMaterialsInput request = getEncryptionMaterialsRequest(encryptionContext, policy, suite);
        return MplTestServerClients.withRetry(() -> mpl.testServer().getEncryptionMaterials(request));
    }

    /** GetEncryptionMaterials, which must fail with any error. A null {@code suite} lets the CMM choose. */
    FailureCheck getEncryptionMaterialsFails(Map<String, String> encryptionContext,
            CommitmentPolicy policy, AlgorithmSuiteId suite) {
        GetEncryptionMaterialsInput request = getEncryptionMaterialsRequest(encryptionContext, policy, suite);
        return FailureCheck.run(mpl, () ->
            MplTestServerClients.withRetry(() -> mpl.testServer().getEncryptionMaterials(request)));
    }

    /** A DecryptMaterials request for this CMM, with nothing else set. */
    DecryptMaterialsInput.Builder decryptMaterialsRequest() {
        return DecryptMaterialsInput.builder().cmmId(cmmId);
    }

    /**
     * The DecryptMaterials request for {@code encrypted}.
     * It has the suite, encrypted data keys and encryption context of {@code encrypted}, as a message header would.
     * A test can change the request before it sends it with {@link #decryptMaterials(DecryptMaterialsInput.Builder)}.
     */
    DecryptMaterialsInput.Builder decryptMaterialsRequest(GetEncryptionMaterialsOutput encrypted,
            CommitmentPolicy policy) {
        return decryptMaterialsRequest()
            .algorithmSuiteId(encrypted.getAlgorithmSuiteId())
            .encryptedDataKeys(encrypted.getEncryptedDataKeys())
            .encryptionContext(encrypted.getEncryptionContext())
            .commitmentPolicy(policy);
    }

    /** DecryptMaterials for {@code encrypted}, which must succeed. */
    DecryptMaterialsOutput decryptMaterials(GetEncryptionMaterialsOutput encrypted, CommitmentPolicy policy) {
        return decryptMaterials(decryptMaterialsRequest(encrypted, policy));
    }

    /** DecryptMaterials, which must succeed. */
    DecryptMaterialsOutput decryptMaterials(DecryptMaterialsInput.Builder request) {
        DecryptMaterialsInput input = request.build();
        return MplTestServerClients.withRetry(() -> mpl.testServer().decryptMaterials(input));
    }

    /** DecryptMaterials, which must fail with any error. */
    FailureCheck decryptMaterialsFails(DecryptMaterialsInput.Builder request) {
        DecryptMaterialsInput input = request.build();
        return FailureCheck.run(mpl, () ->
            MplTestServerClients.withRetry(() -> mpl.testServer().decryptMaterials(input)));
    }

    private GetEncryptionMaterialsInput getEncryptionMaterialsRequest(Map<String, String> encryptionContext,
            CommitmentPolicy policy, AlgorithmSuiteId suite) {
        GetEncryptionMaterialsInput.Builder builder = GetEncryptionMaterialsInput.builder()
            .cmmId(cmmId)
            .encryptionContext(encryptionContext)
            .commitmentPolicy(policy);
        return (suite == null ? builder : builder.algorithmSuiteId(suite)).build();
    }
}
