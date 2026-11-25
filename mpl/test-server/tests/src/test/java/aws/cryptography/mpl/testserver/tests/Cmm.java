package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;

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
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * A Default CMM that a language's MPL created, and the two CMM calls.
 *
 * <p>The CMM lives in that language's test server, and this object holds the ID that the test server gave it.
 * {@link #defaultCmm} builds it over a Raw AES keyring with one fixed AES-256 wrapping key.
 * So the CMMs that two languages build can decrypt each other's encrypted data keys.
 */
final class Cmm {

    static final String NAMESPACE = "mpl-test-server";
    static final String KEY_NAME = "default-cmm-key";

    /** The key the Default CMM adds to the context for a signing suite. */
    static final String PUBLIC_KEY_EC_KEY = "aws-crypto-public-key";

    private static final byte[] WRAPPING_KEY = new byte[32];

    static {
        for (int i = 0; i < WRAPPING_KEY.length; i++) WRAPPING_KEY[i] = (byte) (i + 7);
    }

    private final MPLTestServerClient testServer;
    private final String cmmId;

    private Cmm(MPLTestServerClient testServer, String cmmId) {
        this.testServer = testServer;
        this.cmmId = cmmId;
    }

    /** A new Default CMM in {@code testServer}'s MPL, over the fixed Raw AES keyring. */
    static Cmm defaultCmm(MPLTestServerClient testServer) {
        String keyringId = MplTestServerClients.withRetry(() ->
            testServer.createRawAesKeyring(CreateRawAesKeyringInput.builder()
                .keyNamespace(NAMESPACE)
                .keyName(KEY_NAME)
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())).getKeyringId();
        return new Cmm(testServer, MplTestServerClients.withRetry(() ->
            testServer.createDefaultCmm(CreateDefaultCmmInput.builder()
                .keyringId(keyringId)
                .build())).getCmmId());
    }

    /** GetEncryptionMaterials, which must succeed. A null {@code suite} lets the CMM choose. */
    GetEncryptionMaterialsOutput getEncryptionMaterials(Map<String, String> encryptionContext,
            CommitmentPolicy policy, AlgorithmSuiteId suite) {
        GetEncryptionMaterialsInput request = getEncryptionMaterialsRequest(encryptionContext, policy, suite);
        return MplTestServerClients.withRetry(() -> testServer.getEncryptionMaterials(request));
    }

    /** GetEncryptionMaterials, which must fail. A null {@code suite} lets the CMM choose. */
    MPLClientError getEncryptionMaterialsFails(Map<String, String> encryptionContext,
            CommitmentPolicy policy, AlgorithmSuiteId suite) {
        GetEncryptionMaterialsInput request = getEncryptionMaterialsRequest(encryptionContext, policy, suite);
        return assertThrows(MPLClientError.class, () -> testServer.getEncryptionMaterials(request));
    }

    /**
     * The DecryptMaterials request for {@code encrypted}.
     * It has the suite, encrypted data keys and encryption context of {@code encrypted}, as a message header would.
     * A test can change the request before it sends it with {@link #decryptMaterials(DecryptMaterialsInput.Builder)}.
     */
    DecryptMaterialsInput.Builder decryptMaterialsRequest(GetEncryptionMaterialsOutput encrypted,
            CommitmentPolicy policy) {
        return DecryptMaterialsInput.builder()
            .cmmId(cmmId)
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
        return MplTestServerClients.withRetry(() -> testServer.decryptMaterials(input));
    }

    /** DecryptMaterials, which must fail. */
    MPLClientError decryptMaterialsFails(DecryptMaterialsInput.Builder request) {
        DecryptMaterialsInput input = request.build();
        return assertThrows(MPLClientError.class, () -> testServer.decryptMaterials(input));
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
