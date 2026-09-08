package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeySource;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.BeaconVersion;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair test for the searchable-encryption (beacon) configuration
 * prerequisite of the §0.3.3 beacon rewrite. The bounded property under test: a
 * transforms client configured with a standard beacon writes the beacon
 * attribute ({@code aws_dbe_b_<name>}) when it encrypts an item on the write
 * path, and the item still round-trips back to plaintext on the read path (with
 * the beacon attribute stripped).
 *
 * <p>This exercises the live beacon key store — a branch-key store in DynamoDB
 * ({@code KeyStoreDdbTable}) whose beacon keys are wrapped by KMS — so it proves
 * the whole beacon-config plumbing (SearchConfig → BeaconVersion → key store →
 * beacon key fetch) works end to end and cross-language. The FilterExpression
 * rewrite itself (ScanInputTransform / QueryInputTransform) builds on this
 * configuration and is a separate follow-up.
 */
class BeaconConfigTests {

    // CI-provisioned beacon key store resources in the test account (resource
    // identifiers, not secrets; access is gated by AWS credentials).
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    /** The beacon attribute the {@code secret} standard beacon writes. */
    private static final String SECRET_BEACON = "aws_dbe_b_" + SECRET;

    @ParameterizedTest(name = "[beacon] standard beacon written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void standardBeaconWrittenAndItemRoundTrips(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        String encryptClientId = createBeaconTransformsClient(encryptClient);
        Map<String, AttributeValue> encrypted = encryptClient.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(encryptClientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(plaintext).build())
                .build()).getTransformedInput().getItem();

        // Write path: the standard beacon on `secret` is written as aws_dbe_b_secret.
        assertTrue(encrypted.containsKey(SECRET_BEACON),
            "standard beacon '" + SECRET_BEACON + "' must be written on encrypt on " + pair);

        // Read path: the item still decrypts to plaintext, beacon attribute stripped.
        String decryptClientId = createBeaconTransformsClient(decryptClient);
        Map<String, AttributeValue> recovered = decryptClient.getItemOutputTransform(
            GetItemOutputTransformInput.builder()
                .clientId(decryptClientId)
                .originalInput(GetItemInput.builder()
                    .tableName(TABLE)
                    .key(Map.of(PK, plaintext.get(PK)))
                    .build())
                .sdkOutput(GetItemOutput.builder().item(encrypted).build())
                .build()).getTransformedOutput().getItem();

        assertNotNull(recovered, "GetItemOutputTransform returned no item on " + pair);
        for (Map.Entry<String, AttributeValue> entry : plaintext.entrySet()) {
            AttributeValue actual = recovered.get(entry.getKey());
            assertNotNull(actual,
                "recovered item missing attribute '" + entry.getKey() + "' on " + pair);
            assertEquals(entry.getValue().getS(), actual.getS(),
                "attribute '" + entry.getKey() + "' did not round-trip on " + pair);
        }
        assertFalse(recovered.containsKey(SECRET_BEACON),
            "beacon attribute must be stripped from the decrypted item on " + pair);
    }

    @ParameterizedTest(name = "[beacon] ScanInputTransform rewrites beacon filter {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanInputTransformRewritesBeaconFilter(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);

        ScanInput transformed = client.scanInputTransform(
            ScanInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ScanInput.builder()
                    .tableName(TABLE)
                    .filterExpression("#s = :s")
                    .expressionAttributeNames(Map.of("#s", SECRET))
                    .expressionAttributeValues(Map.of(":s",
                        AttributeValue.builder().s("hunter2").build()))
                    .build())
                .build()).getTransformedInput();

        assertEquals(SECRET_BEACON, transformed.getExpressionAttributeNames().get("#s"),
            "the beaconed attribute name must be rewritten to its beacon on " + pair);
        assertNotEquals("hunter2", transformed.getExpressionAttributeValues().get(":s").getS(),
            "the compared value must be replaced by its beacon on " + pair);
    }

    @ParameterizedTest(name = "[beacon] QueryInputTransform rewrites beacon filter {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryInputTransformRewritesBeaconFilter(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);

        QueryInput transformed = client.queryInputTransform(
            QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#s = :s")
                    .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET))
                    .expressionAttributeValues(Map.of(
                        ":p", AttributeValue.builder().s("item-1").build(),
                        ":s", AttributeValue.builder().s("hunter2").build()))
                    .build())
                .build()).getTransformedInput();

        assertEquals(SECRET_BEACON, transformed.getExpressionAttributeNames().get("#s"),
            "the beaconed filter attribute must be rewritten to its beacon on " + pair);
        assertEquals(PK, transformed.getExpressionAttributeNames().get("#p"),
            "the non-beaconed partition key must be left unchanged on " + pair);
        assertNotEquals("hunter2", transformed.getExpressionAttributeValues().get(":s").getS(),
            "the compared beacon value must be replaced by its beacon on " + pair);
    }

    /**
     * Build a transforms client whose table config carries a standard beacon on
     * {@code secret}, keyed by the live branch-key store, over the shared
     * AWS-KMS item keyring.
     */
    private static String createBeaconTransformsClient(DBESDKTestServerClient client) {
        SearchConfig search = SearchConfig.builder()
            .writeVersion(1)
            .versions(List.of(BeaconVersion.builder()
                .version(1)
                .keyStore(BeaconKeyStore.builder()
                    .ddbTableName(KEY_STORE_TABLE)
                    .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                    .kmsKeyArn(KEY_STORE_KMS_ARN)
                    .build())
                .keySource(BeaconKeySource.builder()
                    .single(SingleKeyStore.builder()
                        .keyId(BRANCH_KEY_ID)
                        .cacheTtlSeconds(3600)
                        .build())
                    .build())
                .standardBeacons(List.of(StandardBeacon.builder()
                    .name(SECRET)
                    .length(24)
                    .build()))
                .build()))
            .build();

        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder()
                    .kmsKeyId(DbeTestHelpers.resolveKmsKeyArn())
                    .build())
                .build())
            .search(search)
            .build();
        return client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(TABLE).build())
            .getClientId();
    }
}
