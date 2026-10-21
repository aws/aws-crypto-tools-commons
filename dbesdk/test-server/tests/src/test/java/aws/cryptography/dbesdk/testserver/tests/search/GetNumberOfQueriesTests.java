package aws.cryptography.dbesdk.testserver.tests.search;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeySource;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.BeaconVersion;
import aws.cryptography.dbesdk.testserver.client.model.CompoundBeacon;
import aws.cryptography.dbesdk.testserver.client.model.Constructor;
import aws.cryptography.dbesdk.testserver.client.model.ConstructorPart;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.EncryptedPart;
import aws.cryptography.dbesdk.testserver.client.model.GetNumberOfQueriesInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.QueryInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language coverage for the {@code GetNumberOfQueries} transforms
 * operation (Dafny {@code BeaconPartition.dfy}: {@code TestNumberOfQueriesPartition*}).
 * For a beacon divided across {@code N} partitions, a Query touching it must be
 * split into {@code N} beacon sub-queries; a beacon with no partitions needs 1.
 *
 * <p>Gated on {@code beacon-partitions}: the java-v3-server both lacks that
 * feature and does not expose {@code GetNumberOfQueries} in the published
 * {@code aws-database-encryption-sdk-dynamodb 3.8.1} Java API (it is present in
 * the Rust and .NET runtimes), so the gate correctly runs these only on the
 * Rust/.NET targets. The operation computes from the beacon config, so it runs
 * on the target's encrypt endpoint.
 */
class GetNumberOfQueriesTests {

    private static final String BEACON = "std2";
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    static java.util.stream.Stream<LanguageServerTarget> targets() {
        return DbeTestHelpers.targets().stream();
    }

    /** ENCRYPT_AND_SIGN {@link #BEACON} attribute plus the partition key. */
    private static Map<String, CryptoAction> beaconActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(BEACON, CryptoAction.ENCRYPT_AND_SIGN);
        return actions;
    }

    /**
     * A transforms client with a single standard beacon over {@link #BEACON}.
     * When {@code partitions}/{@code maximum} are non-null the beacon is divided
     * across {@code partitions} partitions (needs {@code beacon-partitions}).
     */
    private static String newBeaconTransformsClient(
            DBESDKTestServerClient client, Integer partitions, Integer maximum) {
        StandardBeacon.Builder beacon = StandardBeacon.builder().name(BEACON).length(24);
        if (partitions != null) {
            beacon.numberOfPartitions(partitions);
        }
        BeaconVersion.Builder version = BeaconVersion.builder()
            .version(1)
            .keyStore(BeaconKeyStore.builder()
                .ddbTableName(KEY_STORE_TABLE)
                .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                .kmsKeyArn(KEY_STORE_KMS_ARN)
                .build())
            .keySource(BeaconKeySource.builder()
                .single(SingleKeyStore.builder().keyId(BRANCH_KEY_ID).cacheTtlSeconds(3600).build())
                .build())
            .standardBeacons(List.of(beacon.build()));
        if (maximum != null) {
            version.maximumNumberOfPartitions(maximum);
        }
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(beaconActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .search(SearchConfig.builder().writeVersion(1).versions(List.of(version.build())).build())
            .build();
        return client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(TABLE).build())
            .getClientId();
    }

    private static int numberOfQueries(DBESDKTestServerClient client, String clientId) {
        Map<String, AttributeValue> values = new LinkedHashMap<>();
        values.put(":std2", AttributeValue.builder().s("query-value").build());
        return client.getNumberOfQueries(GetNumberOfQueriesInput.builder()
            .clientId(clientId)
            .sdkInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression(BEACON + " = :std2")
                .expressionAttributeValues(values)
                .build())
            .build()).getNumberOfQueries();
    }

    @ParameterizedTest(name = "GetNumberOfQueries equals the beacon partition count {0}")
    @MethodSource("targets")
    void numberOfQueriesReflectsPartitionCount(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Beacon over 5 partitions (maximum 6): a query touching it needs 5 sub-queries.
        String clientId = newBeaconTransformsClient(client, 5, 6);
        //= specification/dynamodb-encryption-client/ddb-get-number-of-queries.md#input
        //= type=test
        //# This operation MUST return the number of queries necessary.
        assertEquals(5, numberOfQueries(client, clientId),
            "a 5-partition beacon query must report 5 sub-queries on " + target);
    }

    @ParameterizedTest(name = "GetNumberOfQueries is one without partitions {0}")
    @MethodSource("targets")
    void numberOfQueriesIsOneWithoutPartitions(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // No partitions configured: a query needs a single beacon sub-query.
        String clientId = newBeaconTransformsClient(client, null, null);
        assertEquals(1, numberOfQueries(client, clientId),
            "an unpartitioned beacon query must report 1 sub-query on " + target);
    }

    @ParameterizedTest(name = "GetNumberOfQueries equals a 25-partition count {0}")
    @MethodSource("targets")
    void numberOfQueriesForTwentyFivePartitions(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny BeaconPartition.dfy#TestNumberOfQueriesPartition25: 25 partitions -> 25 queries.
        String clientId = newBeaconTransformsClient(client, 25, 26);
        assertEquals(25, numberOfQueries(client, clientId),
            "a 25-partition beacon query must report 25 sub-queries on " + target);
    }

    @ParameterizedTest(name = "GetNumberOfQueries uses the LCM of multiple beacons, capped at maximum {0}")
    @MethodSource("targets")
    void numberOfQueriesUsesLcmOfMultipleBeaconsCappedAtMaximum(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestNumberOfQueriesWithMultipleBeaconsConfigured: std2 over 3 partitions and
        // std4 over 5 -> LCM(3,5)=15 under a generous max, then capped at the configured max.
        Map<String, AttributeValue> values = new LinkedHashMap<>();
        values.put(":std2", s("v2"));
        values.put(":std4", s("v4"));
        String cond = "std4 = :std4 AND std2 = :std2";
        Map<String, CryptoAction> actions = actionsFor("std2", "std4");

        String lcmClient = createClient(client, versionBase()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("std2").length(24).numberOfPartitions(3).build(),
                StandardBeacon.builder().name("std4").length(24).numberOfPartitions(5).build()))
            .maximumNumberOfPartitions(16)
            .build(), actions);
        //= specification/dynamodb-encryption-client/ddb-get-number-of-queries.md#behavior
        //= type=test
        //# The calculated value is the least common multiple of the number of partitions for each of the beacons involved.
        assertEquals(15, count(client, lcmClient, cond, values),
            "two beacons over 3 and 5 partitions must yield LCM(3,5)=15 on " + target);

        String cappedClient = createClient(client, versionBase()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("std2").length(24).numberOfPartitions(3).build(),
                StandardBeacon.builder().name("std4").length(24).numberOfPartitions(5).build()))
            .maximumNumberOfPartitions(6)
            .build(), actions);
        assertEquals(6, count(client, cappedClient, cond, values),
            "the query count must be capped at maximumNumberOfPartitions (6) on " + target);
    }

    @ParameterizedTest(name = "GetNumberOfQueries for a compound beacon uses its participating parts {0}")
    @MethodSource("targets")
    void numberOfQueriesForCompoundBeacon(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestNumberOfQueriesForCompoundBeacons: NameTitle over Name (3) and Title (5)
        // -> LCM(3,5)=15.
        BeaconVersion version = versionBase()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("Name").length(32).numberOfPartitions(3).build(),
                StandardBeacon.builder().name("Title").length(32).numberOfPartitions(5).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name("Name").prefix("N_").build(),
                EncryptedPart.builder().name("Title").prefix("T_").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("NameTitle")
                .split(".")
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name("Name").required(true).build(),
                        ConstructorPart.builder().name("Title").required(true).build()))
                    .build()))
                .build()))
            .maximumNumberOfPartitions(16)
            .build();
        String clientId = createClient(client, version, actionsFor("Name", "Title"));
        Map<String, AttributeValue> values = new LinkedHashMap<>();
        values.put(":nt", s("N_MyName.T_MyTitle"));
        assertEquals(15, count(client, clientId, "NameTitle = :nt", values),
            "a compound beacon over 3- and 5-partition parts must yield LCM(3,5)=15 on " + target);
    }

    @ParameterizedTest(name = "maximumNumberOfPartitions at the 255 boundary is rejected {0}")
    @MethodSource("targets")
    void maximumPartitionsAtBoundaryRejected(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestBoundaryPartitionValues: MAX_PARTITION_COUNT is 255, so
        // maximumNumberOfPartitions must be strictly less than 255.
        assertThrows(DBESDKTestServerException.class, () -> createClient(client, versionBase()
            .standardBeacons(List.of(StandardBeacon.builder().name("std2").length(24).build()))
            .maximumNumberOfPartitions(255)
            .build(), actionsFor("std2")),
            "maximumNumberOfPartitions == 255 must be rejected on " + target);
    }

    @ParameterizedTest(name = "GetNumberOfQueries computes a large valid partition count {0}")
    @MethodSource("targets")
    void numberOfQueriesForLargeValidPartitionCount(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestBoundaryPartitionValues: max=128 (valid, < 255) with a beacon over 64
        // partitions -> 64 queries.
        String clientId = newBeaconTransformsClient(client, 64, 128);
        assertEquals(64, numberOfQueries(client, clientId),
            "a 64-partition beacon under max 128 must report 64 sub-queries on " + target);
    }

    @ParameterizedTest(name = "an unconstrained beacon inherits defaultNumberOfPartitions {0}")
    @MethodSource("targets")
    void unconstrainedBeaconInheritsDefaultPartitions(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestDefaultPartitionInheritance: max=10, default=3; a beacon with no explicit
        // numberOfPartitions inherits the default (3), not the maximum (10).
        BeaconVersion version = versionBase()
            .standardBeacons(List.of(StandardBeacon.builder().name("std2").length(24).build()))
            .maximumNumberOfPartitions(10)
            .defaultNumberOfPartitions(3)
            .build();
        String clientId = createClient(client, version, actionsFor("std2"));
        assertEquals(3, numberOfQueries(client, clientId),
            "an unconstrained beacon must inherit defaultNumberOfPartitions (3), not the maximum on "
                + target);
    }

    @ParameterizedTest(name = "defaultNumberOfPartitions without a maximum is rejected {0}")
    @MethodSource("targets")
    void defaultPartitionsWithoutMaximumRejected(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestDefaultPartitionsWithoutMaxPartitionsFail.
        assertThrows(DBESDKTestServerException.class, () -> createClient(client, versionBase()
            .standardBeacons(List.of(StandardBeacon.builder().name("std2").length(24).build()))
            .defaultNumberOfPartitions(3)
            .build(), actionsFor("std2")),
            "defaultNumberOfPartitions without maximumNumberOfPartitions must be rejected on " + target);
    }

    @ParameterizedTest(name = "defaultNumberOfPartitions at or above maximum is rejected {0}")
    @MethodSource("targets")
    void defaultPartitionsAtOrAboveMaximumRejected(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestInvalidMaxNumberOfPartitionsConfigError: default must be 0 < default < maximum.
        assertThrows(DBESDKTestServerException.class, () -> createClient(client, versionBase()
            .standardBeacons(List.of(StandardBeacon.builder().name("std2").length(24).build()))
            .maximumNumberOfPartitions(5)
            .defaultNumberOfPartitions(5)
            .build(), actionsFor("std2")),
            "defaultNumberOfPartitions == maximum must be rejected on " + target);
        assertThrows(DBESDKTestServerException.class, () -> createClient(client, versionBase()
            .standardBeacons(List.of(StandardBeacon.builder().name("std2").length(24).build()))
            .maximumNumberOfPartitions(5)
            .defaultNumberOfPartitions(10)
            .build(), actionsFor("std2")),
            "defaultNumberOfPartitions > maximum must be rejected on " + target);
    }

    @ParameterizedTest(name = "a beacon numberOfPartitions at or above maximum is rejected {0}")
    @MethodSource("targets")
    void constrainedBeaconAtOrAboveMaximumRejected(LanguageServerTarget target) {
        FeatureGate.require(Set.of("beacon-partitions"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // Dafny TestConstrainedBeacon*: a beacon's numberOfPartitions must be < the maximum.
        assertThrows(DBESDKTestServerException.class, () -> createClient(client, versionBase()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("std2").length(24).numberOfPartitions(5).build()))
            .maximumNumberOfPartitions(5)
            .build(), actionsFor("std2")),
            "a beacon numberOfPartitions == maximum must be rejected on " + target);
        assertThrows(DBESDKTestServerException.class, () -> createClient(client, versionBase()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("std2").length(24).numberOfPartitions(10).build()))
            .maximumNumberOfPartitions(5)
            .build(), actionsFor("std2")),
            "a beacon numberOfPartitions > maximum must be rejected on " + target);
    }

    // -----------------------------------------------------------------
    // Config + query helpers shared by the partition-count behaviors.
    // -----------------------------------------------------------------

    private static BeaconVersion.Builder versionBase() {
        return BeaconVersion.builder()
            .version(1)
            .keyStore(BeaconKeyStore.builder()
                .ddbTableName(KEY_STORE_TABLE)
                .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                .kmsKeyArn(KEY_STORE_KMS_ARN)
                .build())
            .keySource(BeaconKeySource.builder()
                .single(SingleKeyStore.builder().keyId(BRANCH_KEY_ID).cacheTtlSeconds(3600).build())
                .build());
    }

    private static String createClient(
            DBESDKTestServerClient client, BeaconVersion version, Map<String, CryptoAction> actions) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(actions)
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .search(SearchConfig.builder().writeVersion(1).versions(List.of(version)).build())
            .build();
        return client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(TABLE).build())
            .getClientId();
    }

    private static int count(
            DBESDKTestServerClient client, String clientId,
            String keyCondition, Map<String, AttributeValue> values) {
        return client.getNumberOfQueries(GetNumberOfQueriesInput.builder()
            .clientId(clientId)
            .sdkInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression(keyCondition)
                .expressionAttributeValues(values)
                .build())
            .build()).getNumberOfQueries();
    }

    private static Map<String, CryptoAction> actionsFor(String... encryptAndSign) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        for (String attr : encryptAndSign) {
            actions.put(attr, CryptoAction.ENCRYPT_AND_SIGN);
        }
        return actions;
    }

    private static AttributeValue s(String value) {
        return AttributeValue.builder().s(value).build();
    }
}
