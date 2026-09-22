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

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsMrkMultiKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
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
 * AWS-KMS MRK multi-keyring LIVE cross-language interop — a writer on runtime A
 * encrypts with an {@code AwsKmsMrkMultiKeyring} whose generator is a
 * multi-Region key (primary in us-west-2). A reader on runtime B decrypts the
 * item under a plain MRK keyring pinned to the SAME key's us-east-1 REPLICA,
 * proving an MRK-wrapped data key is decryptable through the replica in another
 * Region — the multi-Region property, exercised across languages.
 */
class AwsKmsMrkMultiKeyringInteropTests {

    // A multi-Region key provisioned for this test: primary in us-west-2,
    // replica in us-east-1 (alias/dbesdk-test-server-mrk in both Regions).
    private static final String MRK_PRIMARY_WEST2 =
        "arn:aws:kms:us-west-2:370957321024:key/mrk-b567507b37b840aebc54fdf17cf9553c";
    private static final String MRK_REPLICA_EAST1 =
        "arn:aws:kms:us-east-1:370957321024:key/mrk-b567507b37b840aebc54fdf17cf9553c";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static String newClient(DBESDKTestServerClient client, Keyring keyring) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(keyring)
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    private static Keyring mrkMultiKeyring() {
        return Keyring.builder()
            .awsKmsMrkMultiKeyring(AwsKmsMrkMultiKeyringConfig.builder()
                .generator(MRK_PRIMARY_WEST2)
                .kmsKeyIds(List.of(resolveKmsKeyArn()))
                .build())
            .build();
    }

    @ParameterizedTest(name = "AwsKmsMrkMulti keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void mrkMultiKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms-mrk"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newClient(encryptClient, mrkMultiKeyring());
        String decryptClientId = newClient(decryptClient, mrkMultiKeyring());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("aws-kms-mrk-multi", decrypted, pair);
    }

    @ParameterizedTest(name = "MRK-multi item decrypts via the us-east-1 replica keyring {0}")
    @MethodSource("testPairs")
    void mrkMultiItemDecryptsViaReplicaRegion(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms-mrk"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newClient(encryptClient, mrkMultiKeyring());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());

        // Decrypt under a plain MRK keyring pinned to the us-east-1 replica.
        String replicaClientId = newClient(decryptClient, Keyring.builder()
            .awsKmsMrk(AwsKmsMrkKeyringConfig.builder().kmsKeyId(MRK_REPLICA_EAST1).build())
            .build());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(replicaClientId).encryptedItem(item).build());
        assertPlaintextPreserved("mrk-multi -> us-east-1 replica", decrypted, pair);
    }
}
