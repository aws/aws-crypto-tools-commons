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
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsMrkDiscoveryKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsMrkKeyringConfig;
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
 * AWS-KMS MRK discovery keyring LIVE cross-language interop — a writer on runtime
 * A encrypts under a plain MRK keyring (a multi-Region key, primary in
 * us-west-2). A reader on runtime B decrypts under an MRK discovery keyring
 * pinned to us-east-1: no key id is configured, so the key is discovered from the
 * item's EDK and the MRK ARN is rewritten to the us-east-1 replica. This proves
 * cross-Region MRK discovery across languages; a non-matching account filter must
 * be rejected.
 */
class AwsKmsMrkDiscoveryKeyringInteropTests {

    // Multi-Region key provisioned for this test (primary us-west-2, replica us-east-1).
    private static final String MRK_PRIMARY_WEST2 =
        "arn:aws:kms:us-west-2:370957321024:key/mrk-b567507b37b840aebc54fdf17cf9553c";
    private static final String DISCOVERY_REGION = "us-east-1";

    // arn : partition : service : region : account : resource
    private static final String[] KEY_ARN_PARTS = resolveKmsKeyArn().split(":");
    private static final String PARTITION = KEY_ARN_PARTS[1];
    private static final String ACCOUNT_ID = KEY_ARN_PARTS[4];

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static String newMrkEncryptClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKmsMrk(AwsKmsMrkKeyringConfig.builder().kmsKeyId(MRK_PRIMARY_WEST2).build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    private static String newMrkDiscoveryClient(DBESDKTestServerClient client, List<String> accountIds) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKmsMrkDiscovery(AwsKmsMrkDiscoveryKeyringConfig.builder()
                    .region(DISCOVERY_REGION)
                    .discoveryFilter(DiscoveryFilter.builder()
                        .partition(PARTITION)
                        .accountIds(accountIds)
                        .build())
                    .build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    @ParameterizedTest(name = "MRK item decrypts under a us-east-1 discovery keyring {0}")
    @MethodSource("testPairs")
    void mrkItemDecryptsUnderReplicaRegionDiscovery(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms-mrk"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newMrkEncryptClient(encryptClient);
        String decryptClientId = newMrkDiscoveryClient(decryptClient, List.of(ACCOUNT_ID));
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("mrk-discovery", decrypted, pair);
    }

    @ParameterizedTest(name = "MRK discovery with a non-matching account filter is rejected {0}")
    @MethodSource("testPairs")
    void mrkDiscoveryWithNonMatchingAccountRejected(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms-mrk"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newMrkEncryptClient(encryptClient);
        String decryptClientId = newMrkDiscoveryClient(decryptClient, List.of("000000000000"));
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptClientId).encryptedItem(item).build()),
            "an MRK discovery keyring whose filter excludes the key's account must not decrypt on " + pair);
    }
}
