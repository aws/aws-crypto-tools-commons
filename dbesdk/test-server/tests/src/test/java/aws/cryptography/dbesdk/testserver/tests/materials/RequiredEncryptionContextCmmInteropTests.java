package aws.cryptography.dbesdk.testserver.tests.materials;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.RequiredEncryptionContextCmmConfig;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * RequiredEncryptionContext CMM behavior with the DBE item encryptor. Cohesive
 * property: an item encryptor backed by a RequiredEncryptionContext CMM that
 * requires one or more of DBE's base-context keys round-trips. Those keys live
 * in the signed Encryption Context but are not stored on the wire; the DBE
 * decrypt path reconstructs the base context from the item and configuration,
 * which is exactly what satisfies the required-key contract on read.
 *
 * <p>The required keys must be keys the item encryptor actually places in the
 * base context ({@code aws-crypto-table-name}, {@code aws-crypto-partition-name});
 * these are the ones reconstructable at decrypt without a caller-supplied EC
 * (the item encryptor exposes no decrypt-time EC input).
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #requiredPartitionNameKeyRoundTrip}</li>
 *   <li>{@link #requiredTableNameKeyRoundTrip}</li>
 *   <li>{@link #requiredMultipleBaseContextKeysRoundTrip}</li>
 *   <li>{@link #requiredEcEncryptedItemDecryptsUnderDefaultCmm} — interop with a plain Default CMM</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 4 assertions × pairs²}.
 */
class RequiredEncryptionContextCmmInteropTests {

    private static final String PARTITION_NAME_KEY = "aws-crypto-partition-name";
    private static final String TABLE_NAME_KEY = "aws-crypto-table-name";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /** A RequiredEncryptionContext CMM over a Default CMM over the shared AWS-KMS keyring. */
    private static String newRequiredEcClient(DBESDKTestServerClient client, List<String> requiredKeys) {
        CryptographicMaterialsManager underlying = CryptographicMaterialsManager.builder()
            .defaultMember(DefaultCmmConfig.builder().keyring(kmsKeyring()).build())
            .build();
        CryptographicMaterialsManager requiredEc = CryptographicMaterialsManager.builder()
            .requiredEncryptionContext(RequiredEncryptionContextCmmConfig.builder()
                .underlyingCMM(underlying)
                .requiredEncryptionContextKeys(requiredKeys)
                .build())
            .build();
        return createWithCmm(client, requiredEc);
    }

    private static Keyring kmsKeyring() {
        return Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
            .build();
    }

    private static String createWithCmm(DBESDKTestServerClient client, CryptographicMaterialsManager cmm) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .cmm(cmm)
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    private DecryptItemOutput roundTripWithRequiredEc(TargetPair pair, List<String> requiredKeys) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newRequiredEcClient(encryptClient, requiredKeys);
        String decryptClientId = newRequiredEcClient(decryptClient, requiredKeys);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        return decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
    }

    @ParameterizedTest(name = "required aws-crypto-partition-name round-trip {0}")
    @MethodSource("testPairs")
    void requiredPartitionNameKeyRoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of("required-encryption-context-cmm"), pair);
        assertPlaintextPreserved("required-partition",
            roundTripWithRequiredEc(pair, List.of(PARTITION_NAME_KEY)), pair);
    }

    @ParameterizedTest(name = "required aws-crypto-table-name round-trip {0}")
    @MethodSource("testPairs")
    void requiredTableNameKeyRoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of("required-encryption-context-cmm"), pair);
        assertPlaintextPreserved("required-table",
            roundTripWithRequiredEc(pair, List.of(TABLE_NAME_KEY)), pair);
    }

    @ParameterizedTest(name = "required multiple base-context keys round-trip {0}")
    @MethodSource("testPairs")
    void requiredMultipleBaseContextKeysRoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of("required-encryption-context-cmm"), pair);
        assertPlaintextPreserved("required-multi",
            roundTripWithRequiredEc(pair, List.of(PARTITION_NAME_KEY, TABLE_NAME_KEY)), pair);
    }

    /**
     * An item encrypted through a RequiredEncryptionContext CMM must decrypt
     * under a plain Default CMM on the same keyring: the required base-context
     * keys are reconstructed by the decrypt path regardless of whether the
     * decrypting client wraps its CMM in RequiredEncryptionContext.
     */
    @ParameterizedTest(name = "RequiredEC-encrypted item decrypts under Default CMM {0}")
    @MethodSource("testPairs")
    void requiredEcEncryptedItemDecryptsUnderDefaultCmm(TargetPair pair) {
        FeatureGate.require(Set.of("required-encryption-context-cmm"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newRequiredEcClient(encryptClient, List.of(PARTITION_NAME_KEY));
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, standardActions(), List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("required-ec->default", decrypted, pair);
    }
}
