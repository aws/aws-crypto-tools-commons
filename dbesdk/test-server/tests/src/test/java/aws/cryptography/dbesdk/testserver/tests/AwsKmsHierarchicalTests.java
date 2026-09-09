package aws.cryptography.dbesdk.testserver.tests;

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
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsHierarchicalKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * AWS-KMS-Hierarchical keyring behavior. Cohesive property: an item encrypted
 * under an {@code AwsKmsHierarchical} keyring — whose data keys are wrapped by a
 * branch key persisted in a DynamoDB key store and itself protected by KMS —
 * round-trips across the full cross-language pair matrix, and the branch-key
 * hierarchy is genuinely in effect (a plain {@code AwsKms} keyring on the item
 * key cannot decrypt a hierarchical-encrypted item).
 *
 * <p>Exercises the live branch-key store ({@code KeyStoreDdbTable}, branch key
 * {@code 040a32a8-…}, wrapped by KMS key {@code 9d989aa2-…}) — the same keystore
 * the beacon tests use. Branch-key retrieval reaches DynamoDB + KMS on
 * Encrypt/Decrypt.
 *
 * <p>Distinct from {@link DbeRoundTripTests} (plain {@code AwsKms} / {@code RawAes})
 * and {@link AwsKmsMrkTests} (MRK). The hierarchical keyring is its own key
 * hierarchy and is intentionally NOT interoperable with a plain KMS keyring.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #hierarchicalKeyringRoundTripPreservesPlaintext} — hierarchical both ends</li>
 *   <li>{@link #hierarchicalEncryptedItemIsNotDecryptableByPlainKmsKeyring} — cryptographic isolation</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 2 assertions × pairs²}.
 */
class AwsKmsHierarchicalTests {

    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /**
     * Build a DBE client on {@code client} backed by an {@code AwsKmsHierarchical}
     * keyring over the live branch-key store, using the standard v2 schema.
     */
    private static String newHierarchicalClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKmsHierarchical(AwsKmsHierarchicalKeyringConfig.builder()
                    .branchKeyId(BRANCH_KEY_ID)
                    .keyStoreTableName(KEY_STORE_TABLE)
                    .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                    .kmsKeyArn(KEY_STORE_KMS_KEY_ARN)
                    .ttlSeconds(3600)
                    .build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    @ParameterizedTest(name = "hierarchical keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void hierarchicalKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newHierarchicalClient(encryptClient);
        String decryptClientId = newHierarchicalClient(decryptClient);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("hierarchical", decrypted, pair);
    }

    /**
     * A hierarchical-encrypted item's data key is wrapped by the branch key, not
     * by the item KMS key directly, so a plain {@code AwsKms} keyring MUST NOT be
     * able to decrypt it. This proves the branch-key hierarchy is actually in
     * effect (the keyring did not silently fall back to a plain KMS keyring).
     */
    @ParameterizedTest(name = "hierarchical-encrypted item is not decryptable by a plain KMS keyring {0}")
    @MethodSource("testPairs")
    void hierarchicalEncryptedItemIsNotDecryptableByPlainKmsKeyring(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newHierarchicalClient(encryptClient);
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, standardActions(), java.util.List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptClientId).encryptedItem(item).build()));
    }
}
