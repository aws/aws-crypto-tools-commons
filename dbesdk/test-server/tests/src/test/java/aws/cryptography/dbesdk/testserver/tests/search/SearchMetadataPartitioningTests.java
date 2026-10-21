package aws.cryptography.dbesdk.testserver.tests.search;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeySource;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.BeaconVersion;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for beacon partitions — a beacon divided
 * across multiple partitions to smooth its value distribution.
 *
 * <p>Beacon partitions are NOT uniformly available: the Rust and .NET DBE
 * libraries support them, but the pinned Java DBE library (3.8.1) predates the
 * feature. This is modeled by the {@code beacon-partitions} Feature — declared
 * <em>unsupported</em> for the Java Language_Server and <em>supported</em> for
 * Rust and .NET. Every test here calls {@link FeatureGate#require} first, so a
 * pair involving Java is visibly skipped while the Rust/.NET pairs run. The Java
 * server compiles against 3.8.1 precisely because it never wires the partition
 * fields (it declares the feature unsupported and ignores them).
 *
 * <p>Three bounded properties:
 * <ul>
 *   <li>A partitioned standard beacon is written on encrypt and the item still
 *       round-trips on decrypt.</li>
 *   <li>{@code defaultNumberOfPartitions} ≥ {@code maximumNumberOfPartitions} is
 *       rejected at config construction.</li>
 *   <li>a beacon's {@code numberOfPartitions} ≥ the version's
 *       {@code maximumNumberOfPartitions} is rejected at config construction.</li>
 * </ul>
 * The two rejection invariants are grounded in the DBE library's
 * {@code ConfigToInfo} validation (0 &lt; default &lt; max; per-beacon count
 * &lt; max).
 */
class SearchMetadataPartitioningTests {

    private static final String FEATURE = "beacon-partitions";

    // Live beacon key store resources (resource identifiers, not secrets).
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    private static final String SECRET_BEACON = "aws_dbe_b_" + SECRET;

    @ParameterizedTest(name = "[beacon] partitioned beacon written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void partitionedBeaconWrittenAndItemRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        // secret beacon divided across 3 partitions; version caps at 5, default 2.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .defaultNumberOfPartitions(2)
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(SECRET)
                .length(24)
                .numberOfPartitions(3)
                .build())));

        String encryptClientId = createBeaconClient(encryptClient, search);
        Map<String, AttributeValue> encrypted = encryptClient.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(encryptClientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(plaintext).build())
                .build()).getTransformedInput().getItem();

        assertTrue(encrypted.containsKey(SECRET_BEACON),
            "partitioned beacon '" + SECRET_BEACON + "' must be written on encrypt on " + pair);

        String decryptClientId = createBeaconClient(decryptClient, search);
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

    @ParameterizedTest(name = "[beacon] default >= maximum partitions rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void defaultPartitionsAtLeastMaximumIsRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // default (5) is not strictly less than maximum (3).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(3)
            .defaultNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder().name(SECRET).length(24).build())));
        //= specification/searchable-encryption/search-config.md#beacon-version-initialization
        //= type=test
        //# Initialization MUST fail if [default number of partitions](#default-partitions) is greater than or equal to [maximum number of partitions](#max-partitions).
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(client, search),
            "defaultNumberOfPartitions >= maximumNumberOfPartitions must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] beacon partitions >= maximum rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void beaconPartitionsAtLeastMaximumIsRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // the beacon's numberOfPartitions (10) is not less than the maximum (5).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(SECRET)
                .length(24)
                .numberOfPartitions(10)
                .build())));
        //= specification/searchable-encryption/beacons.md#standard-beacon-initialization
        //= type=test
        //# Initialization MUST fail if [number of partitions](#beacon-constraint) is specified, and is greater than or equal to
        //# the maximum number of partitions specified in the [beacon version](search-config.md#beacon-version-initialization).
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(client, search),
            "a beacon's numberOfPartitions >= maximumNumberOfPartitions must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] unicode-named partitioned beacon written + non-empty {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void unicodeBeaconNameWrittenAndValuesHashNonEmpty(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // Dafny BeaconPartition.dfy TestUnicodeBeaconName: a beacon whose name is a
        // Unicode string ("café") is written as aws_dbe_b_<name> with a non-empty
        // hashed String value. Here the beacon is additionally partitioned so it is
        // exercised under the beacon-partitions feature.
        final String unicodeName = "caf\u00e9";
        final String unicodeBeacon = "aws_dbe_b_" + unicodeName;

        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(unicodeName)
                .length(24)
                .numberOfPartitions(3)
                .build())));

        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(unicodeName, CryptoAction.ENCRYPT_AND_SIGN);

        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(unicodeName, AttributeValue.builder().s(unicodeName).build());

        String clientId = createBeaconClient(client, search, actions);
        Map<String, AttributeValue> encrypted = client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build()).getTransformedInput().getItem();

        assertTrue(encrypted.containsKey(unicodeBeacon),
            "unicode-named beacon '" + unicodeBeacon + "' must be written on encrypt on " + pair);
        AttributeValue beacon = encrypted.get(unicodeBeacon);
        assertNotNull(beacon.getS(), "the unicode beacon value must be a String on " + pair);
        assertFalse(beacon.getS().isEmpty(),
            "the unicode beacon hash value must be non-empty on " + pair);
    }

    @ParameterizedTest(name = "[beacon] out-of-range :aws_dbe_partition selector rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void invalidPartitionSelectorInQueryRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // Single-defect: the config is VALID (a standard beacon on `secret` whose
        // partition count inherits maximumNumberOfPartitions = 5). The DEFECT lives
        // in the query: :aws_dbe_partition = 5 is not < the max partitions (5).
        // Dafny BeaconPartition.dfy TestInvalidPartitionOnQuery (partition >= count).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder().name(SECRET).length(24).build())));
        String clientId = createBeaconClient(client, search);

        //= specification/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
        //= type=test
        //# If this value is not of type `N` or fails to hold an integer value
        //# greater than or equal to zero and less than the [max partitions](search-config.md#max-partitions),
        //# an error MUST be returned.
        assertThrows(DBESDKTestServerException.class,
            () -> client.queryInputTransform(QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#s = :s")
                    .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET))
                    .expressionAttributeValues(Map.of(
                        ":p", AttributeValue.builder().s("item-1").build(),
                        ":s", AttributeValue.builder().s("hunter2").build(),
                        ":aws_dbe_partition", AttributeValue.builder().n("5").build()))
                    .build())
                .build()),
            ":aws_dbe_partition >= the number of partitions must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] non-numeric :aws_dbe_partition selector rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void nonNumericPartitionSelectorRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // Single-defect: the config is VALID; the DEFECT is the selector TYPE —
        // :aws_dbe_partition is a String, not the required numeric (N) type.
        // Dafny BeaconPartition.dfy TestInvalidPartitionType (type S / BOOL).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder().name(SECRET).length(24).build())));
        String clientId = createBeaconClient(client, search);

        //= specification/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
        //= type=test
        //# If this value is not of type `N` or fails to hold an integer value
        //# greater than or equal to zero and less than the [max partitions](search-config.md#max-partitions),
        //# an error MUST be returned.
        assertThrows(DBESDKTestServerException.class,
            () -> client.queryInputTransform(QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#s = :s")
                    .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET))
                    .expressionAttributeValues(Map.of(
                        ":p", AttributeValue.builder().s("item-1").build(),
                        ":s", AttributeValue.builder().s("hunter2").build(),
                        ":aws_dbe_partition", AttributeValue.builder().s("2").build()))
                    .build())
                .build()),
            "a non-numeric :aws_dbe_partition selector must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] long-name partitioned beacon accepted + written {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void longNamePartitionBeaconAccepted(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // Dafny BeaconPartition.dfy TestLongAttributeNameForPartitionBeacon: an
        // 80-character attribute name for a constrained (partitioned) standard
        // beacon is a valid configuration (numberOfPartitions 3 < maximum 10). The
        // write path then materializes aws_dbe_b_<longName>.
        final String longName =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        final String longBeacon = "aws_dbe_b_" + longName;

        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(10)
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(longName)
                .length(24)
                .numberOfPartitions(3)
                .build())));

        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(longName, CryptoAction.ENCRYPT_AND_SIGN);

        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(longName, AttributeValue.builder().s("value").build());

        // Config construction must be accepted (the long name is a valid config).
        String clientId = createBeaconClient(client, search, actions);
        Map<String, AttributeValue> encrypted = client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build()).getTransformedInput().getItem();

        assertTrue(encrypted.containsKey(longBeacon),
            "long-named partitioned beacon '" + longBeacon + "' must be written on encrypt on "
                + pair);
        assertFalse(encrypted.get(longBeacon).getS().isEmpty(),
            "the long-named beacon hash value must be non-empty on " + pair);
    }

    @ParameterizedTest(name = "[beacon] query rewrite over mixed partitioned beacons {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryRewriteOverMixedPartitionedBeacons(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // A table whose beacons carry DIFFERENT partition counts (secret=2, note=3),
        // queried together. GetNumberOfQueries = min(max, LCM(2,3)) = min(6,6) = 6 =
        // the max, so there is no partition-augmentation OR-expansion; the input
        // transform rewrites BOTH beacon names/values for the selected partition 0.
        // Dafny BeaconPartition.dfy TestQueryMixedTableBeaconPartitions.
        final String note = "note";
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(6)
            .standardBeacons(List.of(
                StandardBeacon.builder().name(SECRET).length(24).numberOfPartitions(2).build(),
                StandardBeacon.builder().name(note).length(24).numberOfPartitions(3).build())));

        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(note, CryptoAction.ENCRYPT_AND_SIGN);

        String clientId = createBeaconClient(client, search, actions);

        //= specification/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
        //= type=test
        //# If the name is used indirectly through the ExpressionAttributeNames mapping,
        //# the name MUST be changed in the ExpressionAttributeNames. For example if the query is
        //# "#Beacon = :value" and ExpressionAttributeNames holds (#Beacon = MyBeacon),
        //# the query must remain unchanged and ExpressionAttributeNames changed to (#Beacon = aws_dbe_b_MyBeacon).
        QueryInput transformed = client.queryInputTransform(QueryInputTransformInput.builder()
            .clientId(clientId)
            .sdkInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression("#p = :p")
                .filterExpression("#s = :s AND #n = :n")
                .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET, "#n", note))
                .expressionAttributeValues(Map.of(
                    ":p", AttributeValue.builder().s("item-1").build(),
                    ":s", AttributeValue.builder().s("hunter2").build(),
                    ":n", AttributeValue.builder().s("memo").build(),
                    ":aws_dbe_partition", AttributeValue.builder().n("0").build()))
                .build())
            .build()).getTransformedInput();

        assertEquals("aws_dbe_b_" + SECRET, transformed.getExpressionAttributeNames().get("#s"),
            "the partitioned `secret` beacon name must be rewritten to its beacon on " + pair);
        assertEquals("aws_dbe_b_" + note, transformed.getExpressionAttributeNames().get("#n"),
            "the partitioned `note` beacon name must be rewritten to its beacon on " + pair);
        assertEquals(PK, transformed.getExpressionAttributeNames().get("#p"),
            "the non-beaconed partition key must be left unchanged on " + pair);
        assertNotEquals("hunter2", transformed.getExpressionAttributeValues().get(":s").getS(),
            "the `secret` beacon value must be beaconized on " + pair);
        assertNotEquals("memo", transformed.getExpressionAttributeValues().get(":n").getS(),
            "the `note` beacon value must be beaconized on " + pair);
    }

    @ParameterizedTest(name = "[beacon] missing beacon attribute produces no beacon {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void missingBeaconAttributeProducesNoBeacon(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption", FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // A partitioned standard beacon on `secret`; the encrypted item OMITS the
        // `secret` attribute, so no beacon value is produced for it.
        // Dafny BeaconPartition.dfy TestMissingBeaconAttributeWithPartitions.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder().name(SECRET).length(24).build())));
        String clientId = createBeaconClient(client, search);

        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(PUBLIC, AttributeValue.builder().s("hello world").build());

        Map<String, AttributeValue> encrypted = client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build()).getTransformedInput().getItem();

        //= specification/searchable-encryption/beacons.md#value-for-a-standard-beacon
        //= type=test
        //# This operation MUST return no value if the associated field does not exist in the record
        assertFalse(encrypted.containsKey(SECRET_BEACON),
            "no beacon must be written for the absent `secret` attribute on " + pair);
    }

    private static SearchConfig beaconSearch(BeaconVersion.Builder version) {
        return SearchConfig.builder()
            .writeVersion(1)
            .versions(List.of(version
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
                .build()))
            .build();
    }

    private static String createBeaconClient(DBESDKTestServerClient client, SearchConfig search) {
        return createBeaconClient(client, search, standardActions());
    }

    private static String createBeaconClient(
            DBESDKTestServerClient client, SearchConfig search, Map<String, CryptoAction> actions) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(actions)
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
