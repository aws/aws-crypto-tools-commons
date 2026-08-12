package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmInput;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmOutput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringOutput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full MPL round trip across the pairwise matrix:
 * CreateRawAesKeyring → CreateDefaultCmm → GetEncryptionMaterials on server A
 * → DecryptMaterials on server B using EDKs from A.
 */
public class RawAesRoundTripTest {

    private static final byte[] WRAPPING_KEY = new byte[32];
    static {
        for (int i = 0; i < WRAPPING_KEY.length; i++) WRAPPING_KEY[i] = (byte) i;
    }

    @TestFactory
    Stream<DynamicTest> rawAes256RoundTrip() {
        List<LanguageServerRegistry.EndpointPair> pairs = LanguageServerRegistry.instance().pairs();
        Assumptions.assumeFalse(pairs.isEmpty(), "No targets configured");

        return pairs.stream().map(pair -> DynamicTest.dynamicTest(
            "RawAES-256: encrypt-materials@" + pair.server1().language()
                + " → decrypt-materials@" + pair.server2().language(),
            () -> {
                MPLTestServerClient encServer = TestServerClients.forEndpoint(pair.server1().endpoint());
                MPLTestServerClient decServer = TestServerClients.forEndpoint(pair.server2().endpoint());

                // Create keyring on encrypt server
                CreateRawAesKeyringOutput keyringOut = encServer.createRawAesKeyring(
                    CreateRawAesKeyringInput.builder()
                        .keyNamespace("mpl-test-server")
                        .keyName("round-trip-key")
                        .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                        .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                        .build());
                assertNotNull(keyringOut.getKeyringId());
                assertFalse(keyringOut.getKeyringId().isBlank());

                // Create default CMM on encrypt server
                CreateDefaultCmmOutput cmmOut = encServer.createDefaultCmm(
                    CreateDefaultCmmInput.builder()
                        .keyringId(keyringOut.getKeyringId())
                        .build());
                assertNotNull(cmmOut.getCmmId());

                // GetEncryptionMaterials
                Map<String, String> ec = new HashMap<>();
                ec.put("purpose", "cross-lang-test");

                GetEncryptionMaterialsOutput encMaterials = encServer.getEncryptionMaterials(
                    GetEncryptionMaterialsInput.builder()
                        .cmmId(cmmOut.getCmmId())
                        .encryptionContext(ec)
                        .commitmentPolicy(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build());

                assertNotNull(encMaterials.getPlaintextDataKey());
                assertTrue(encMaterials.getPlaintextDataKey().remaining() > 0);
                assertNotNull(encMaterials.getEncryptedDataKeys());
                assertFalse(encMaterials.getEncryptedDataKeys().isEmpty());
                assertNotNull(encMaterials.getAlgorithmSuiteId());

                // Create keyring + CMM on decrypt server (same key)
                CreateRawAesKeyringOutput decKeyringOut = decServer.createRawAesKeyring(
                    CreateRawAesKeyringInput.builder()
                        .keyNamespace("mpl-test-server")
                        .keyName("round-trip-key")
                        .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                        .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                        .build());

                CreateDefaultCmmOutput decCmmOut = decServer.createDefaultCmm(
                    CreateDefaultCmmInput.builder()
                        .keyringId(decKeyringOut.getKeyringId())
                        .build());

                // DecryptMaterials on server B
                DecryptMaterialsOutput decMaterials = decServer.decryptMaterials(
                    DecryptMaterialsInput.builder()
                        .cmmId(decCmmOut.getCmmId())
                        .algorithmSuiteId(encMaterials.getAlgorithmSuiteId())
                        .encryptedDataKeys(encMaterials.getEncryptedDataKeys())
                        .encryptionContext(encMaterials.getEncryptionContext())
                        .commitmentPolicy(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build());

                assertNotNull(decMaterials.getPlaintextDataKey());
                // The decrypted PDK must match the one from encryption
                assertEquals(encMaterials.getPlaintextDataKey(), decMaterials.getPlaintextDataKey());
            }));
    }
}
