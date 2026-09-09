package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AsSet;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeySource;
import aws.cryptography.dbesdk.testserver.client.model.BeaconKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.BeaconStyle;
import aws.cryptography.dbesdk.testserver.client.model.BeaconVersion;
import aws.cryptography.dbesdk.testserver.client.model.CompoundBeacon;
import aws.cryptography.dbesdk.testserver.client.model.Constructor;
import aws.cryptography.dbesdk.testserver.client.model.ConstructorPart;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.EncryptedPart;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PartOnly;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.Shared;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the three standard-beacon styles (§0.3.6),
 * building on the beacon configuration proven by {@link BeaconConfigTests}. Each
 * style has a distinct, spec-grounded observable effect on the written item:
 *
 * <ul>
 *   <li><em>Shared.</em> A beacon declared {@code shared(other)} calculates its
 *       value as the {@code other} beacon, so for an equal value the two beacon
 *       attributes are equal — where two independent (non-shared) beacons would
 *       differ (their keys are derived per beacon name).</li>
 *   <li><em>PartOnly.</em> A {@code partOnly} beacon is never stored standalone
 *       (spec: "The Standard Beacon MUST NOT be stored in the item"), yet is
 *       usable as a part of a compound beacon, which IS written.</li>
 *   <li><em>AsSet.</em> A beacon over a Set attribute declared {@code asSet} is
 *       stored as a Set of the per-element beacon values (spec).</li>
 * </ul>
 *
 * <p>All exercise the live beacon key store; configs are grounded in the DBE
 * {@code BeaconStylesSearchableEncryptionExample}.
 */
class BeaconStyleTests {

    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    private static final String FIRST = "first";
    private static final String ALIAS = "alias";
    private static final String LAST = "last";
    private static final String TAGS = "tags";

    static java.util.stream.Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    @ParameterizedTest(name = "[beacon] shared beacon matches the beacon it shares with {0}")
    @MethodSource("testPairs")
    void sharedBeaconMatchesTheBeaconItSharesWith(TargetPair pair) {
        // Two E&S attributes with the same value; `alias` shares `first`'s beacon.
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(ALIAS, CryptoAction.ENCRYPT_AND_SIGN);
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(FIRST, AttributeValue.builder().s("john").build());
        item.put(ALIAS, AttributeValue.builder().s("john").build());

        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        // Shared: alias computes as first, so for an equal value the beacons match.
        SearchConfig shared = beaconSearch(BeaconVersion.builder().standardBeacons(List.of(
            StandardBeacon.builder().name(FIRST).length(10).build(),
            StandardBeacon.builder().name(ALIAS).length(10)
                .style(BeaconStyle.builder().shared(Shared.builder().other(FIRST).build()).build())
                .build())));
        Map<String, AttributeValue> sharedItem = encrypt(client, actions, shared, item);
        assertEquals(sharedItem.get("aws_dbe_b_" + FIRST), sharedItem.get("aws_dbe_b_" + ALIAS),
            "a shared beacon must equal the beacon it shares with for an equal value on " + pair);

        // Control: two independent beacons on equal values differ (per-name keys).
        SearchConfig independent = beaconSearch(BeaconVersion.builder().standardBeacons(List.of(
            StandardBeacon.builder().name(FIRST).length(10).build(),
            StandardBeacon.builder().name(ALIAS).length(10).build())));
        Map<String, AttributeValue> independentItem = encrypt(client, actions, independent, item);
        assertNotEquals(
            independentItem.get("aws_dbe_b_" + FIRST), independentItem.get("aws_dbe_b_" + ALIAS),
            "independent beacons on an equal value must differ (control) on " + pair);
    }

    @ParameterizedTest(name = "[beacon] partOnly beacon is not stored standalone but usable in a compound {0}")
    @MethodSource("testPairs")
    void partOnlyBeaconIsNotStoredStandaloneButUsableInCompound(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(FIRST, AttributeValue.builder().s("john").build());
        item.put(LAST, AttributeValue.builder().s("doe").build());

        // `first` is partOnly and used only in the compound `fc`; `last` is a plain beacon.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10)
                    .style(BeaconStyle.builder().partOnly(PartOnly.builder().build()).build())
                    .build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("fc").split(".")
                .constructors(List.of(Constructor.builder().parts(List.of(
                    ConstructorPart.builder().name(FIRST).required(true).build(),
                    ConstructorPart.builder().name(LAST).required(true).build())).build()))
                .build())));

        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> encrypted = encrypt(client, actions, search, item);

        assertFalse(encrypted.containsKey("aws_dbe_b_" + FIRST),
            "a partOnly beacon must NOT be stored standalone on " + pair);
        assertTrue(encrypted.containsKey("aws_dbe_b_" + LAST),
            "a non-partOnly beacon must be stored standalone on " + pair);
        assertTrue(encrypted.containsKey("aws_dbe_b_fc"),
            "the compound beacon using the partOnly part must be stored on " + pair);
    }

    @ParameterizedTest(name = "[beacon] asSet beacon is stored as a Set of per-element beacons {0}")
    @MethodSource("testPairs")
    void asSetBeaconIsStoredAsASetOfPerElementBeacons(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(TAGS, CryptoAction.ENCRYPT_AND_SIGN);
        List<String> elements = List.of("alpha", "beta", "gamma");
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(TAGS, AttributeValue.builder().ss(elements).build());

        SearchConfig search = beaconSearch(BeaconVersion.builder().standardBeacons(List.of(
            StandardBeacon.builder().name(TAGS).length(10)
                .style(BeaconStyle.builder().asSet(AsSet.builder().build()).build())
                .build())));

        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> encrypted = encrypt(client, actions, search, item);

        AttributeValue beacon = encrypted.get("aws_dbe_b_" + TAGS);
        assertNotNull(beacon, "the asSet beacon must be written on " + pair);
        assertNotNull(beacon.getSs(), "the asSet beacon must be stored as a String Set on " + pair);
        assertEquals(elements.size(), beacon.getSs().size(),
            "the asSet beacon must have one beacon value per Set element on " + pair);
    }

    /** Encrypt {@code item} through a transforms client built from {@code actions} + {@code search}. */
    private static Map<String, AttributeValue> encrypt(DBESDKTestServerClient client,
            Map<String, CryptoAction> actions, SearchConfig search, Map<String, AttributeValue> item) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(actions)
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(DbeTestHelpers.resolveKmsKeyArn()).build())
                .build())
            .search(search)
            .build();
        String clientId = client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(TABLE).build())
            .getClientId();
        return client.putItemInputTransform(PutItemInputTransformInput.builder()
            .clientId(clientId)
            .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
            .build()).getTransformedInput().getItem();
    }

    /** Wrap a beacon version in a SearchConfig against the live key store. */
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
}
