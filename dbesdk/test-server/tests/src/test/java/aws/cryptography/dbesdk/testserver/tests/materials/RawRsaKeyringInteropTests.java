package aws.cryptography.dbesdk.testserver.tests.materials;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEAlgorithmSuiteId;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PaddingScheme;
import aws.cryptography.dbesdk.testserver.client.model.RawRsaKeyringConfig;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Raw-RSA keyring LIVE cross-language interop — a writer on runtime A wraps the
 * data key with the RSA public key; a reader on runtime B unwraps it with the
 * RSA private key. The key material is an offline PEM pair checked in under
 * {@code /raw-rsa/}, so no KMS/network is involved — the only axis under test is
 * cross-language RSA-wrap compatibility.
 *
 * <p>The asymmetric raw-RSA keyring is used with a symmetric-signing (SYMSIG)
 * suite, matching {@link KmsRsaKeyringInteropTests}.
 */
class RawRsaKeyringInteropTests {

    private static final String RAW_RSA_NAMESPACE = "raw-rsa";
    private static final String RAW_RSA_KEY_NAME = "dbe-test-rsa-key";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static ByteBuffer pem(String resource) {
        try (InputStream in = RawRsaKeyringInteropTests.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("missing test resource " + resource);
            }
            return ByteBuffer.wrap(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String newRawRsaClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .algorithmSuiteId(
                DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
            .keyring(Keyring.builder()
                .rawRsa(RawRsaKeyringConfig.builder()
                    .keyNamespace(RAW_RSA_NAMESPACE)
                    .keyName(RAW_RSA_KEY_NAME)
                    .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
                    .publicKey(pem("/raw-rsa/public.pem"))
                    .privateKey(pem("/raw-rsa/private.pem"))
                    .build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    @ParameterizedTest(name = "RawRsa keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void rawRsaKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        FeatureGate.requireRawRsaPaddings(Set.of("OAEP_SHA256_MGF1"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newRawRsaClient(encryptClient);
        String decryptClientId = newRawRsaClient(decryptClient);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("raw-rsa", decrypted, pair);
    }

    @ParameterizedTest(name = "RawRsa-encrypted item is not decryptable by a plain KMS keyring {0}")
    @MethodSource("testPairs")
    void rawRsaEncryptedItemIsNotDecryptableByPlainKmsKeyring(TargetPair pair) {
        FeatureGate.requireRawRsaPaddings(Set.of("OAEP_SHA256_MGF1"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newRawRsaClient(encryptClient);
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, standardActions(), List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptClientId).encryptedItem(item).build()),
            "a plain KMS keyring must not decrypt a raw-RSA-wrapped item on " + pair);
    }
}
