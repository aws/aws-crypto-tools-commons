package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for beacon partitions (§0.3.6) — a beacon divided
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
class BeaconPartitionsTests {

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
        FeatureGate.require(Set.of(FEATURE), pair);

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
        FeatureGate.require(Set.of(FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // default (5) is not strictly less than maximum (3).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(3)
            .defaultNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder().name(SECRET).length(24).build())));
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(client, search),
            "defaultNumberOfPartitions >= maximumNumberOfPartitions must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] beacon partitions >= maximum rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void beaconPartitionsAtLeastMaximumIsRejected(TargetPair pair) {
        FeatureGate.require(Set.of(FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // the beacon's numberOfPartitions (10) is not less than the maximum (5).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .maximumNumberOfPartitions(5)
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(SECRET)
                .length(24)
                .numberOfPartitions(10)
                .build())));
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(client, search),
            "a beacon's numberOfPartitions >= maximumNumberOfPartitions must be rejected on " + pair);
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
