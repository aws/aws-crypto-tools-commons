package aws.cryptography.mpl.testserver.tests.meta;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmInput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.GenericServerError;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.InitializeEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.mpl.testserver.client.model.OnEncryptInput;
import aws.cryptography.mpl.testserver.tests.MplTestServerClients;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The harness's own wire contract, per target: handles resolve only to the
 * resource kind that created them, and the two modeled errors arrive as distinct
 * types. A server that answered a bad handle with an MPL error (or the reverse)
 * would make every conformance failure ambiguous.
 */
public class HandleAndErrorContractTest {

    private static final String UNKNOWN_ID = "00000000-0000-4000-8000-000000000000";

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    @ParameterizedTest(name = "unknown keyring handle is a GenericServerError {0}")
    @MethodSource("targets")
    void unknownKeyringHandle(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptionMaterials materials = initializedMaterials(client);

        GenericServerError error = assertThrows(GenericServerError.class, () ->
            client.onEncrypt(OnEncryptInput.builder()
                .keyringId(UNKNOWN_ID)
                .materials(materials)
                .build()));
        assertFalse(error.getMessage().isBlank());
    }

    @ParameterizedTest(name = "unknown CMM handle is a GenericServerError {0}")
    @MethodSource("targets")
    void unknownCmmHandle(LanguageServerTarget target) {
        FeatureGate.require(Set.of("default-cmm"), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        assertThrows(GenericServerError.class, () ->
            client.getEncryptionMaterials(GetEncryptionMaterialsInput.builder()
                .cmmId(UNKNOWN_ID)
                .encryptionContext(Map.of())
                .commitmentPolicy(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build()));
    }

    @ParameterizedTest(name = "keyring handle used as a CMM handle is a GenericServerError {0}")
    @MethodSource("targets")
    void keyringHandleUsedAsCmm(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes", "default-cmm"), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String keyringId = rawAesKeyring(client);

        assertThrows(GenericServerError.class, () ->
            client.getEncryptionMaterials(GetEncryptionMaterialsInput.builder()
                .cmmId(keyringId)
                .encryptionContext(Map.of())
                .commitmentPolicy(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build()));
    }

    @ParameterizedTest(name = "CMM handle used as a keyring handle is a GenericServerError {0}")
    @MethodSource("targets")
    void cmmHandleUsedAsKeyring(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes", "default-cmm"), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = client.createDefaultCmm(CreateDefaultCmmInput.builder()
            .keyringId(rawAesKeyring(client))
            .build()).getCmmId();
        EncryptionMaterials materials = initializedMaterials(client);

        assertThrows(GenericServerError.class, () ->
            client.onEncrypt(OnEncryptInput.builder()
                .keyringId(cmmId)
                .materials(materials)
                .build()));
    }

    /** The MPL rejects a 16-byte key for AES-256 wrapping; that must arrive as MPLClientError. */
    @ParameterizedTest(name = "MPL rejection is an MPLClientError {0}")
    @MethodSource("targets")
    void mplRejectionIsMplClientError(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        MPLClientError error = assertThrows(MPLClientError.class, () ->
            client.createRawAesKeyring(CreateRawAesKeyringInput.builder()
                .keyNamespace("mpl-test-server")
                .keyName("wrong-length-key")
                .wrappingKey(ByteBuffer.wrap(new byte[16]))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build()));
        assertFalse(error.getMessage().isBlank());
    }

    private static String rawAesKeyring(MPLTestServerClient client) {
        return client.createRawAesKeyring(CreateRawAesKeyringInput.builder()
            .keyNamespace("mpl-test-server")
            .keyName("handle-contract-key")
            .wrappingKey(ByteBuffer.wrap(new byte[32]))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build()).getKeyringId();
    }

    private static EncryptionMaterials initializedMaterials(MPLTestServerClient client) {
        return client.initializeEncryptionMaterials(InitializeEncryptionMaterialsInput.builder()
            .algorithmSuiteId(AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .encryptionContext(Map.of())
            .requiredEncryptionContextKeys(List.of())
            .build()).getMaterials();
    }
}
