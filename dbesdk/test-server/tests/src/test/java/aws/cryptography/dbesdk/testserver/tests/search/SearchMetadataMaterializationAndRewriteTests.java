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
import aws.cryptography.dbesdk.testserver.client.model.QueryOutput;
import aws.cryptography.dbesdk.testserver.client.model.QueryOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanOutput;
import aws.cryptography.dbesdk.testserver.client.model.ScanOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair test for the searchable-encryption (beacon) configuration
 * prerequisite of the beacon rewrite. The bounded property under test: a
 * transforms client configured with a standard beacon writes the beacon
 * attribute ({@code aws_dbe_b_<name>}) when it encrypts an item on the write
 * path, and the item still round-trips back to plaintext on the read path (with
 * the beacon attribute stripped).
 *
 * <p>This exercises the live beacon key store — a branch-key store in DynamoDB
 * ({@code KeyStoreDdbTable}) whose beacon keys are wrapped by KMS — so it proves
 * the whole beacon-config plumbing (SearchConfig → BeaconVersion → key store →
 * beacon key fetch) works end to end and cross-language. Building on that
 * configuration, this class also covers the FilterExpression rewrite
 * ({@code ScanInputTransform} / {@code QueryInputTransform}) and the
 * output-transform re-filter that drops beacon false-positives on the decrypted
 * results ({@code ScanOutputTransform} / {@code QueryOutputTransform}).
 */
class SearchMetadataMaterializationAndRewriteTests {

    // CI-provisioned beacon key store resources in the test account (resource
    // identifiers, not secrets; access is gated by AWS credentials).
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    /** The beacon attribute the {@code secret} standard beacon writes. */
    private static final String SECRET_BEACON = "aws_dbe_b_" + SECRET;

    /** A second ENCRYPT_AND_SIGN attribute used by the beacon-validation tests. */
    private static final String NOTE = "note";
    /** A signed (SIGN_ONLY) map attribute used by the nested-path re-filter test. */
    private static final String DATE = "Date";
    /** The nested key inside {@link #DATE} the nested-path re-filter navigates. */
    private static final String MONTH = "Month";

    @ParameterizedTest(name = "[beacon] standard beacon written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void standardBeaconWrittenAndItemRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
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
        FeatureGate.require(Set.of("searchable-encryption"), pair);
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
        FeatureGate.require(Set.of("searchable-encryption"), pair);
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

    @ParameterizedTest(name = "[beacon] ScanOutputTransform re-filters decrypted items {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanOutputTransformReFiltersDecryptedItems(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);

        // A beacon filter is imprecise server-side (beacon collisions), so a Scan
        // returns a superset; ScanOutputTransform decrypts each item and re-applies
        // the ORIGINAL filter on plaintext, dropping the false positives. Encrypt
        // one matching and one non-matching item, then feed both to the output
        // transform as if the beacon scan had returned them together.
        Map<String, AttributeValue> matching = encryptItem(client, clientId, "item-match", "matchme");
        Map<String, AttributeValue> other = encryptItem(client, clientId, "item-other", "nomatch");

        ScanOutput transformed = client.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ScanInput.builder()
                    .tableName(TABLE)
                    .filterExpression("#s = :s")
                    .expressionAttributeNames(Map.of("#s", SECRET))
                    .expressionAttributeValues(Map.of(":s",
                        AttributeValue.builder().s("matchme").build()))
                    .build())
                .sdkOutput(ScanOutput.builder().items(List.of(matching, other)).build())
                .build()).getTransformedOutput();

        List<Map<String, AttributeValue>> items = transformed.getItems();
        assertNotNull(items, "ScanOutputTransform returned no items on " + pair);
        assertEquals(1, items.size(),
            "re-filter must drop the non-matching item, keeping only the exact match on " + pair);
        assertEquals("matchme", items.get(0).get(SECRET).getS(),
            "the surviving item must be the one whose decrypted 'secret' matches the filter on "
                + pair);
    }

    /** Encrypt an item ({@code PK}, {@code secret}) through the beacon write path. */
    private static Map<String, AttributeValue> encryptItem(
            DBESDKTestServerClient client, String clientId, String pk, String secret) {
        Map<String, AttributeValue> item = new HashMap<>(canonicalPlaintext());
        item.put(PK, AttributeValue.builder().s(pk).build());
        item.put(SECRET, AttributeValue.builder().s(secret).build());
        return client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build()).getTransformedInput().getItem();
    }

    /**
     * Run ScanOutputTransform with {@code filterExpression} over two encrypted
     * items (secret = {@code a} and secret = {@code b}) and return the decrypted
     * {@code secret} values that survive the re-filter, so a test can assert
     * exactly which items the re-filter kept.
     */
    private static Set<String> reFilterSurvivors(
            DBESDKTestServerClient client, String clientId, String a, String b,
            String filterExpression, Map<String, AttributeValue> values) {
        Map<String, AttributeValue> itemA = encryptItem(client, clientId, "item-a", a);
        Map<String, AttributeValue> itemB = encryptItem(client, clientId, "item-b", b);
        ScanOutput out = client.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ScanInput.builder()
                    .tableName(TABLE)
                    .filterExpression(filterExpression)
                    .expressionAttributeNames(Map.of("#s", SECRET))
                    .expressionAttributeValues(values)
                    .build())
                .sdkOutput(ScanOutput.builder().items(List.of(itemA, itemB)).build())
                .build()).getTransformedOutput();
        Set<String> survivors = new java.util.HashSet<>();
        if (out.getItems() != null) {
            for (Map<String, AttributeValue> item : out.getItems()) {
                survivors.add(item.get(SECRET).getS());
            }
        }
        return survivors;
    }

    private static AttributeValue s(String v) {
        return AttributeValue.builder().s(v).build();
    }

    /**
     * A standard (equality) beacon supports only equality-family re-filtering;
     * an ordering/prefix operator on the beaconed attribute must be rejected.
     */
    private static void assertStandardBeaconRejects(
            DBESDKTestServerClient client, String clientId,
            String filterExpression, Map<String, AttributeValue> values) {
        Map<String, AttributeValue> item = encryptItem(client, clientId, "item-a", "aaa");
        assertThrows(DBESDKTestServerException.class, () -> client.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ScanInput.builder()
                    .tableName(TABLE)
                    .filterExpression(filterExpression)
                    .expressionAttributeNames(Map.of("#s", SECRET))
                    .expressionAttributeValues(values)
                    .build())
                .sdkOutput(ScanOutput.builder().items(List.of(item)).build())
                .build()));
    }

    /** The QueryOutputTransform path enforces the same standard-beacon operator rule. */
    private static void assertQueryStandardBeaconRejects(
            DBESDKTestServerClient client, String clientId,
            String filterExpression, Map<String, AttributeValue> values) {
        Map<String, AttributeValue> item = encryptItem(client, clientId, "item-1", "aaa");
        Map<String, AttributeValue> vals = new HashMap<>(values);
        vals.put(":p", s("item-1"));
        assertThrows(DBESDKTestServerException.class, () -> client.queryOutputTransform(
            QueryOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression(filterExpression)
                    .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET))
                    .expressionAttributeValues(vals)
                    .build())
                .sdkOutput(QueryOutput.builder().items(List.of(item)).build())
                .build()));
    }

    @ParameterizedTest(name = "[beacon] Query standard beacon rejects begins_with {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryStandardBeaconRejectsBeginsWith(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        assertQueryStandardBeaconRejects(client, clientId, "begins_with(#s, :p2)",
            Map.of(":p2", s("prefix")));
    }

    @ParameterizedTest(name = "[beacon] Query standard beacon rejects between {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryStandardBeaconRejectsBetween(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        assertQueryStandardBeaconRejects(client, clientId, "#s BETWEEN :lo AND :hi",
            Map.of(":lo", s("a"), ":hi", s("c")));
    }

    @ParameterizedTest(name = "[beacon] standard beacon rejects not-equal {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterNotEqualRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // A standard beacon cannot answer '<>' server-side, so DBE rejects it
        // ("The operation '<>' cannot be used with a standard beacon.").
        assertStandardBeaconRejects(client, clientId, "#s <> :v", Map.of(":v", s("aaa")));
    }

    @ParameterizedTest(name = "[beacon] standard beacon rejects less-than {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterLessThanRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        assertStandardBeaconRejects(client, clientId, "#s < :v", Map.of(":v", s("m")));
    }

    @ParameterizedTest(name = "[beacon] standard beacon rejects between {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterBetweenRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        assertStandardBeaconRejects(client, clientId, "#s BETWEEN :lo AND :hi",
            Map.of(":lo", s("a"), ":hi", s("c")));
    }

    @ParameterizedTest(name = "[beacon] re-filter IN {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterIn(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        Set<String> survivors = reFilterSurvivors(client, clientId, "x", "z",
            "#s IN (:a, :b)", Map.of(":a", s("x"), ":b", s("y")));
        assertEquals(Set.of("x"), survivors,
            "re-filter IN must keep only the listed item on " + pair);
    }

    @ParameterizedTest(name = "[beacon] standard beacon rejects begins_with {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterBeginsWithRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        assertStandardBeaconRejects(client, clientId, "begins_with(#s, :p)",
            Map.of(":p", s("prefix")));
    }

    @ParameterizedTest(name = "[beacon] re-filter contains {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterContains(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        Set<String> survivors = reFilterSurvivors(client, clientId, "a-middle-b", "nope",
            "contains(#s, :sub)", Map.of(":sub", s("middle")));
        assertEquals(Set.of("a-middle-b"), survivors,
            "re-filter contains must keep only the substring-bearing item on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter size {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterSize(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        Set<String> survivors = reFilterSurvivors(client, clientId, "12345", "12",
            "size(#s) = :n", Map.of(":n", AttributeValue.builder().n("5").build()));
        assertEquals(Set.of("12345"), survivors,
            "re-filter size() must keep only the item of the given length on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter complex OR {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterComplexOr(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        Set<String> survivors = reFilterSurvivors(client, clientId, "p", "r",
            "#s = :a OR #s = :b", Map.of(":a", s("p"), ":b", s("q")));
        assertEquals(Set.of("p"), survivors,
            "re-filter with an OR of equalities must keep only the matching item on " + pair);
    }

    @ParameterizedTest(name = "[beacon] QueryOutputTransform re-filters decrypted items {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryOutputTransformReFiltersDecryptedItems(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);

        // Same re-filter contract as Scan, but through QueryOutputTransform: the
        // key condition selects the partition (not beaconed, so not re-filtered)
        // and the beacon filter on `secret` is re-applied on the decrypted items.
        // Both items share a partition key so only the filter distinguishes them.
        Map<String, AttributeValue> matching = encryptItem(client, clientId, "item-1", "matchme");
        Map<String, AttributeValue> other = encryptItem(client, clientId, "item-1", "nomatch");

        QueryOutput transformed = client.queryOutputTransform(
            QueryOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#s = :s")
                    .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET))
                    .expressionAttributeValues(Map.of(
                        ":p", s("item-1"),
                        ":s", s("matchme")))
                    .build())
                .sdkOutput(QueryOutput.builder().items(List.of(matching, other)).build())
                .build()).getTransformedOutput();

        assertNotNull(transformed.getItems(), "QueryOutputTransform returned no items on " + pair);
        assertEquals(1, transformed.getItems().size(),
            "Query re-filter must drop the non-matching item on " + pair);
        assertEquals("matchme", transformed.getItems().get(0).get(SECRET).getS(),
            "the surviving item must be the one whose decrypted 'secret' matches the filter on "
                + pair);
    }

    // ------------------------------------------------------------------
    // Black-box re-filter / beacon-validation coverage, grounded in the DBE
    // Dafny FilterExpr test suite. The output re-filter re-applies the ORIGINAL
    // filter on the DECRYPTED items whenever a SearchConfig is present
    // (DDBSupport.dfy ScanOutputForBeacons -> FilterExpr.dfy FilterResults), and
    // the input transform validates the filter against the beacon config
    // (DDBSupport.dfy ScanInputForBeacons/QueryInputForBeacons -> DoBeaconize).
    // A standard (equality) beacon rejects ordering operators, so numeric
    // compare / BETWEEN / nested-path re-filters run over the non-beacon,
    // plaintext-signed `public` (or a signed `Date` map) attribute — exactly as
    // the Dafny suite compares non-beacon fields.
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "[beacon] filter over encrypted un-beaconed field rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void searchEncryptedFieldWithoutBeaconRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // `note` is ENCRYPT_AND_SIGN but carries no beacon; only `secret` is beaconed.
        String clientId = createSearchTransformsClient(
            client, Map.of(NOTE, CryptoAction.ENCRYPT_AND_SIGN), Set.of(SECRET));
        // Dafny FilterExpr.dfy TestNoBeaconFail: beaconizing a filter over an
        // encrypted field that has no beacon fails ("Field <name> is encrypted,
        // and cannot be searched without a beacon.").
        assertThrows(DBESDKTestServerException.class, () -> client.scanInputTransform(
            ScanInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ScanInput.builder()
                    .tableName(TABLE)
                    .filterExpression("#n = :v")
                    .expressionAttributeNames(Map.of("#n", NOTE))
                    .expressionAttributeValues(Map.of(":v", s("anything")))
                    .build())
                .build()));
    }

    @ParameterizedTest(name = "[beacon] value reused in two beacon contexts rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void valueReusedInTwoBeaconContextsRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // Two standard beacons (`secret` and `note`) so a single value can land
        // in two distinct beacon contexts.
        String clientId = createSearchTransformsClient(
            client, Map.of(NOTE, CryptoAction.ENCRYPT_AND_SIGN), Set.of(SECRET, NOTE));
        // Dafny FilterExpr.dfy TestMultiContextFailures
        // (spec ddb-support.md#queryinputforbeacons): a single value used in more
        // than one beacon context (`this = :v OR that = :v`) MUST fail
        // (":v used in two different contexts, which is not allowed.").
        assertThrows(DBESDKTestServerException.class, () -> client.queryInputTransform(
            QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#s = :v OR #n = :v")
                    .expressionAttributeNames(Map.of("#p", PK, "#s", SECRET, "#n", NOTE))
                    .expressionAttributeValues(Map.of(":p", s("item-1"), ":v", s("dup")))
                    .build())
                .build()));
    }

    @ParameterizedTest(name = "[beacon] re-filter malformed number rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterMalformedNumberRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // `public` is signed (non-beacon) so an ordering compare is permitted and
        // reaches numeric parsing. Dafny FilterExpr.dfy TestFilterFailNumeric: a
        // non-numeric N comparison value fails ("Number needs digits either
        // before or after the decimal point.").
        Map<String, AttributeValue> item =
            encryptItemWith(client, clientId, "item-num", "aaa", Map.of(PUBLIC, n("800")));
        assertThrows(DBESDKTestServerException.class, () -> client.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ScanInput.builder()
                    .tableName(TABLE)
                    .filterExpression("#pub < :bad")
                    .expressionAttributeNames(Map.of("#pub", PUBLIC))
                    .expressionAttributeValues(Map.of(":bad", n("foo")))
                    .build())
                .sdkOutput(ScanOutput.builder().items(List.of(item)).build())
                .build()));
    }

    @ParameterizedTest(name = "[beacon] re-filter numeric comparison normalizes {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterNumericComparisonNormalizes(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // Dafny FilterExpr.dfy TestFilterCompareNumeric: N("800") and
        // N("0800.000e0") compare as equal numbers (not equal strings), so `=`
        // and `<=` keep the item while `<` drops it.
        Map<String, AttributeValue> keep =
            encryptItemWith(client, clientId, "item-800", "keep", Map.of(PUBLIC, n("800")));
        Map<String, AttributeValue> other =
            encryptItemWith(client, clientId, "item-900", "other", Map.of(PUBLIC, n("900")));
        List<Map<String, AttributeValue>> items = List.of(keep, other);
        Map<String, String> names = Map.of("#pub", PUBLIC);

        assertEquals(Set.of("keep"),
            survivorsOf(client, clientId, items, "#pub = :v", names, Map.of(":v", n("0800.000e0"))),
            "numeric '=' must normalize 800 vs 0800.000e0 on " + pair);
        assertEquals(Set.of("keep"),
            survivorsOf(client, clientId, items, "#pub <= :v", names, Map.of(":v", n("0800.000e0"))),
            "numeric '<=' must keep the numerically-equal value on " + pair);
        assertEquals(Set.of(),
            survivorsOf(client, clientId, items, "#pub < :v", names, Map.of(":v", n("0800.000e0"))),
            "numeric '<' must drop the numerically-equal value on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter numeric BETWEEN {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterBetweenNumber(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // Dafny FilterExpr.dfy TestFilterBetweenNumber: numeric BETWEEN over a
        // non-beacon field. 52 BETWEEN 9 AND 185 holds; 500 does not.
        Map<String, AttributeValue> inside =
            encryptItemWith(client, clientId, "item-52", "inside", Map.of(PUBLIC, n("52")));
        Map<String, AttributeValue> outside =
            encryptItemWith(client, clientId, "item-500", "outside", Map.of(PUBLIC, n("500")));
        Set<String> survivors = survivorsOf(client, clientId, List.of(inside, outside),
            "#pub BETWEEN :lo AND :hi", Map.of("#pub", PUBLIC),
            Map.of(":lo", n("9"), ":hi", n("185")));
        assertEquals(Set.of("inside"), survivors,
            "numeric BETWEEN must keep only the in-range item on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter resolves indirect names {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterResolvesIndirectNames(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // Dafny FilterExpr.dfy TestFilterIndirectNames: an expression-attribute
        // name (#field) and value (:want) must resolve to the underlying
        // attribute and value before the (beacon equality) re-filter is applied.
        Map<String, AttributeValue> keep = encryptItem(client, clientId, "item-a", "wanted");
        Map<String, AttributeValue> drop = encryptItem(client, clientId, "item-b", "unwanted");
        Set<String> survivors = survivorsOf(client, clientId, List.of(keep, drop),
            "#field = :want", Map.of("#field", SECRET), Map.of(":want", s("wanted")));
        assertEquals(Set.of("wanted"), survivors,
            "indirect #name/:value must resolve and keep only the match on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter over nested document path {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterNestedPathFilter(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // `Date` is a signed (SIGN_ONLY) map, so it stays plaintext-visible in
        // the decrypted item and its nested `Month` is filterable on the
        // re-filter.
        String clientId = createSearchTransformsClient(
            client, Map.of(DATE, CryptoAction.SIGN_ONLY), Set.of(SECRET));
        // Dafny FilterExpr.dfy TestFilterIndirectNamesWithLoc: a nested document
        // path (Date.Month) resolves into the map value and filters on it.
        Map<String, AttributeValue> early = encryptItemWith(client, clientId, "item-mar", "march",
            Map.of(DATE, AttributeValue.builder().m(Map.of(MONTH, s("03"))).build()));
        Map<String, AttributeValue> late = encryptItemWith(client, clientId, "item-nov", "november",
            Map.of(DATE, AttributeValue.builder().m(Map.of(MONTH, s("11"))).build()));
        Set<String> survivors = survivorsOf(client, clientId, List.of(early, late),
            "Date.#m < :v", Map.of("#m", MONTH), Map.of(":v", s("10")));
        assertEquals(Set.of("march"), survivors,
            "nested-path Date.Month re-filter must keep only the matching item on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter attribute operators {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterAttributeOps(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // Dafny FilterExpr.dfy TestFilterAttrOps: attribute_exists /
        // attribute_not_exists / attribute_type / not(...) select by presence and
        // type; ExtractAttributes ignores them, so no beacon is required.
        Map<String, AttributeValue> a = encryptItem(client, clientId, "item-a", "alpha");
        Map<String, AttributeValue> b = encryptItem(client, clientId, "item-b", "beta");
        List<Map<String, AttributeValue>> items = List.of(a, b);
        Set<String> both = Set.of("alpha", "beta");

        assertEquals(both,
            survivorsOf(client, clientId, items, "attribute_exists(#s)",
                Map.of("#s", SECRET), Map.of()),
            "attribute_exists on a present attribute keeps every item on " + pair);
        assertEquals(Set.of(),
            survivorsOf(client, clientId, items, "attribute_exists(#x)",
                Map.of("#x", "missing"), Map.of()),
            "attribute_exists on an absent attribute keeps nothing on " + pair);
        assertEquals(both,
            survivorsOf(client, clientId, items, "attribute_not_exists(#x)",
                Map.of("#x", "missing"), Map.of()),
            "attribute_not_exists on an absent attribute keeps every item on " + pair);
        assertEquals(both,
            survivorsOf(client, clientId, items, "attribute_type(#s, :t)",
                Map.of("#s", SECRET), Map.of(":t", s("S"))),
            "attribute_type S matches the string secret on every item on " + pair);
        assertEquals(Set.of(),
            survivorsOf(client, clientId, items, "not attribute_exists(#s)",
                Map.of("#s", SECRET), Map.of()),
            "not attribute_exists on a present attribute keeps nothing on " + pair);
    }

    @ParameterizedTest(name = "[beacon] re-filter size() IN membership {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void reFilterSizeInMembership(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconTransformsClient(client);
        // Dafny FilterExpr.dfy TestFilterSizeIn: size(attr) IN (...) keeps items
        // whose attribute length is a member of the list. size() needs no beacon.
        Map<String, AttributeValue> five = encryptItem(client, clientId, "item-5", "12345");
        Map<String, AttributeValue> three = encryptItem(client, clientId, "item-3", "999");
        Set<String> survivors = survivorsOf(client, clientId, List.of(five, three),
            "size(#s) IN (:a, :b)", Map.of("#s", SECRET),
            Map.of(":a", n("5"), ":b", n("4")));
        assertEquals(Set.of("12345"), survivors,
            "size() IN must keep only items whose length is listed on " + pair);
    }

    /** @return an {@code N} (numeric) {@link AttributeValue}. */
    private static AttributeValue n(String v) {
        return AttributeValue.builder().n(v).build();
    }

    /**
     * Like {@link #encryptItem} but overlays {@code extra} attributes (e.g. a
     * numeric {@code public} or a nested {@code Date} map) on top of the
     * canonical plaintext before running the beacon write path.
     */
    private static Map<String, AttributeValue> encryptItemWith(
            DBESDKTestServerClient client, String clientId, String pk, String secret,
            Map<String, AttributeValue> extra) {
        Map<String, AttributeValue> item = new HashMap<>(canonicalPlaintext());
        item.put(PK, s(pk));
        item.put(SECRET, s(secret));
        item.putAll(extra);
        return client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build()).getTransformedInput().getItem();
    }

    /**
     * Run {@code ScanOutputTransform} with an arbitrary {@code filterExpression}
     * (and name/value maps) over {@code items} and return the decrypted
     * {@code secret} values that survive the re-filter, so a test can assert
     * exactly which items the re-filter kept. Each item is expected to carry a
     * distinct {@code secret}, which serves as its identity. An empty
     * {@code values} map is treated as "no expression attribute values" so a
     * placeholder-free filter (e.g. {@code attribute_exists(#s)}) is legal.
     */
    private static Set<String> survivorsOf(
            DBESDKTestServerClient client, String clientId,
            List<Map<String, AttributeValue>> items, String filterExpression,
            Map<String, String> names, Map<String, AttributeValue> values) {
        ScanInput.Builder original = ScanInput.builder()
            .tableName(TABLE)
            .filterExpression(filterExpression)
            .expressionAttributeNames(names);
        if (values != null && !values.isEmpty()) {
            original.expressionAttributeValues(values);
        }
        ScanOutput out = client.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(original.build())
                .sdkOutput(ScanOutput.builder().items(items).build())
                .build()).getTransformedOutput();
        Set<String> survivors = new java.util.HashSet<>();
        if (out.getItems() != null) {
            for (Map<String, AttributeValue> item : out.getItems()) {
                survivors.add(item.get(SECRET).getS());
            }
        }
        return survivors;
    }

    /**
     * Build a transforms client with a live-key-store {@link SearchConfig} like
     * {@link #createBeaconTransformsClient}, but with {@code extraActions}
     * overlaid on the standard action map and a standard beacon on each name in
     * {@code beaconAttributes}. Lets a test add an encrypted-but-un-beaconed
     * attribute, a second beacon, or a signed nested attribute.
     */
    private static String createSearchTransformsClient(
            DBESDKTestServerClient client,
            Map<String, CryptoAction> extraActions,
            Set<String> beaconAttributes) {
        Map<String, CryptoAction> actions = new HashMap<>(standardActions());
        actions.putAll(extraActions);

        List<StandardBeacon> beacons = new ArrayList<>();
        for (String name : beaconAttributes) {
            beacons.add(StandardBeacon.builder().name(name).length(24).build());
        }

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
                .standardBeacons(beacons)
                .build()))
            .build();

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
