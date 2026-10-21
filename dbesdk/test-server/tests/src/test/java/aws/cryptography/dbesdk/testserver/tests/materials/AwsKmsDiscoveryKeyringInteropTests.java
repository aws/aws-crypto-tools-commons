package aws.cryptography.dbesdk.testserver.tests.materials;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsDiscoveryKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.DiscoveryFilter;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * AWS-KMS discovery keyring LIVE cross-language interop — a writer on runtime A
 * encrypts under a normal AWS-KMS keyring; a reader on runtime B decrypts under a
 * discovery keyring (no configured key id — the key is discovered from the item's
 * Encrypted Data Key). The discovery filter is derived from the encrypting key's
 * own ARN, so it always matches the item; a deliberately non-matching filter must
 * cause the decrypt to be rejected.
 */
class AwsKmsDiscoveryKeyringInteropTests {

    private static final String[] KEY_ARN_PARTS = resolveKmsKeyArn().split(":");
    // arn : partition : service : region : account : resource
    private static final String PARTITION = KEY_ARN_PARTS[1];
    private static final String ACCOUNT_ID = KEY_ARN_PARTS[4];

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static String newKmsEncryptClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    private static String newDiscoveryClient(DBESDKTestServerClient client, List<String> accountIds) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKmsDiscovery(AwsKmsDiscoveryKeyringConfig.builder()
                    .discoveryFilter(DiscoveryFilter.builder()
                        .partition(PARTITION)
                        .accountIds(accountIds)
                        .build())
                    .build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    @ParameterizedTest(name = "AwsKms-encrypted item decrypts under a discovery keyring {0}")
    @MethodSource("testPairs")
    void awsKmsItemDecryptsUnderDiscovery(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsEncryptClient(encryptClient);
        String decryptClientId = newDiscoveryClient(decryptClient, List.of(ACCOUNT_ID));
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("discovery", decrypted, pair);
    }

    @ParameterizedTest(name = "discovery keyring with a non-matching account filter is rejected {0}")
    @MethodSource("testPairs")
    void discoveryWithNonMatchingAccountRejected(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsEncryptClient(encryptClient);
        String decryptClientId = newDiscoveryClient(decryptClient, List.of("000000000000"));
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptClientId).encryptedItem(item).build()),
            "a discovery keyring whose filter excludes the key's account must not decrypt on " + pair);
    }
}
