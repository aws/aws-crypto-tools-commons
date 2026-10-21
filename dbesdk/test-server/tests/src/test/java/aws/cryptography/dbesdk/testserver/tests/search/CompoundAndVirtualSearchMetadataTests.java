package aws.cryptography.dbesdk.testserver.tests.search;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.EncryptedPart;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.GetPrefix;
import aws.cryptography.dbesdk.testserver.client.model.GetSegment;
import aws.cryptography.dbesdk.testserver.client.model.GetSegments;
import aws.cryptography.dbesdk.testserver.client.model.GetSubstring;
import aws.cryptography.dbesdk.testserver.client.model.GetSuffix;
import aws.cryptography.dbesdk.testserver.client.model.Insert;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.Lower;
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
import aws.cryptography.dbesdk.testserver.client.model.SignedPart;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.dbesdk.testserver.client.model.Upper;
import aws.cryptography.dbesdk.testserver.client.model.VirtualField;
import aws.cryptography.dbesdk.testserver.client.model.VirtualPart;
import aws.cryptography.dbesdk.testserver.client.model.VirtualTransform;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for compound and virtual-field beacons,
 * building on the standard-beacon configuration proven by {@link SearchMetadataMaterializationAndRewriteTests}.
 *
 * <p>Three bounded properties, one per test:
 * <ul>
 *   <li><em>Compound beacon.</em> A compound beacon assembled from two encrypted
 *       parts (each a standard beacon on an {@code ENCRYPT_AND_SIGN} attribute)
 *       is written to {@code aws_dbe_b_<name>} on the write path, and the item
 *       still round-trips to plaintext on the read path.</li>
 *   <li><em>Virtual field.</em> A standard beacon over a virtual field (a value
 *       derived by concatenating two attributes) is written to
 *       {@code aws_dbe_b_<virtualFieldName>}, and the item still round-trips.</li>
 *   <li><em>Compound beacon with a signed part.</em> A compound beacon mixing an
 *       encrypted part (hashed) with a signed part over a {@code SIGN_ONLY}
 *       attribute (included in cleartext) is written and round-trips.</li>
 * </ul>
 *
 * <p>All exercise the live beacon key store (a DynamoDB branch-key store whose
 * keys are wrapped by KMS), so they prove the compound/virtual beacon plumbing
 * works end to end and cross-language. Configs are grounded in the DBE library's
 * own {@code CompoundBeaconSearchableEncryptionExample},
 * {@code VirtualBeaconSearchableEncryptionExample}, and
 * {@code BeaconStylesSearchableEncryptionExample}.
 *
 * <p>An attribute used as an encrypted part is {@code ENCRYPT_AND_SIGN}; a signed
 * part references a {@code SIGN_ONLY} attribute (see {@link #signedPartActions()}).
 */
class CompoundAndVirtualSearchMetadataTests {

    // Live beacon key store resources (resource identifiers, not secrets;
    // access is gated by AWS credentials) — same store as SearchMetadataMaterializationAndRewriteTests.
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    private static final String FIRST = "first";
    private static final String LAST = "last";
    private static final String COMPOUND_NAME = "firstLast";
    private static final String VIRTUAL_NAME = "fullName";
    private static final String SIGNED_COMPOUND_NAME = "firstLastSigned";
    private static final String TAGS = "tags";
    private static final String SCORE = "score";

    @ParameterizedTest(name = "[beacon] compound beacon written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconWrittenAndItemRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Standard beacons on the two encrypted attributes, then a compound
        // beacon that concatenates them as "F-<first>.L-<last>".
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name(COMPOUND_NAME)
                .split(".")
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));

        assertBeaconWrittenAndRoundTrips(pair, search, "aws_dbe_b_" + COMPOUND_NAME, beaconActions());
    }

    @ParameterizedTest(name = "[beacon] virtual-field beacon written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void virtualFieldBeaconWrittenAndItemRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // A virtual field concatenating first+last, and a standard beacon over it.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .virtualFields(List.of(VirtualField.builder()
                .name(VIRTUAL_NAME)
                .parts(List.of(
                    VirtualPart.builder().loc(FIRST).build(),
                    VirtualPart.builder().loc(LAST).build()))
                .build()))
            .standardBeacons(List.of(
                StandardBeacon.builder().name(VIRTUAL_NAME).length(10).build())));

        assertBeaconWrittenAndRoundTrips(pair, search, "aws_dbe_b_" + VIRTUAL_NAME, beaconActions());
    }

    @ParameterizedTest(name = "[beacon] compound beacon with a signed part written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconWithSignedPartWrittenAndItemRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // A compound beacon that concatenates an ENCRYPTED part (a standard beacon
        // over the encrypted `first`, hashed) with a SIGNED part (the plaintext,
        // SIGN_ONLY `last`, included verbatim): "F-<hash(first)>.L-<last>". The
        // signed part is the property under test — it references a signed,
        // non-encrypted attribute and contributes its cleartext value to the
        // beacon (grounded in the DBE BeaconStylesSearchableEncryptionExample).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name(SIGNED_COMPOUND_NAME)
                .split(".")
                .encrypted(List.of(EncryptedPart.builder().name(FIRST).prefix("F-").build()))
                .signed(List.of(SignedPart.builder().name(LAST).prefix("L-").build()))
                .build())));

        assertBeaconWrittenAndRoundTrips(
            pair, search, "aws_dbe_b_" + SIGNED_COMPOUND_NAME, signedPartActions());
    }

    @ParameterizedTest(name = "[beacon] ScanInputTransform rewrites a compound-beacon filter {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanInputTransformRewritesCompoundBeaconFilter(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconClient(client, compoundBeaconSearch(), beaconActions());

        // Query on the assembled compound value "F-<first>.L-<last>" (the part
        // prefixes joined by the split char) — grounded in the DBE compound-beacon
        // example's "L-5678.U-011899988199" query value.
        ScanInput transformed = client.scanInputTransform(ScanInputTransformInput.builder()
            .clientId(clientId)
            .sdkInput(ScanInput.builder()
                .tableName(TABLE)
                .filterExpression("#fl = :v")
                .expressionAttributeNames(Map.of("#fl", COMPOUND_NAME))
                .expressionAttributeValues(Map.of(":v",
                    AttributeValue.builder().s("F-john.L-doe").build()))
                .build())
            .build()).getTransformedInput();

        assertEquals("aws_dbe_b_" + COMPOUND_NAME,
            transformed.getExpressionAttributeNames().get("#fl"),
            "the compound-beacon attribute name must be rewritten to its beacon on " + pair);
        assertNotEquals("F-john.L-doe",
            transformed.getExpressionAttributeValues().get(":v").getS(),
            "the compound value's encrypted parts must be beaconized on " + pair);
    }

    @ParameterizedTest(name = "[beacon] QueryInputTransform rewrites a compound-beacon filter {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryInputTransformRewritesCompoundBeaconFilter(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconClient(client, compoundBeaconSearch(), beaconActions());

        QueryInput transformed = client.queryInputTransform(QueryInputTransformInput.builder()
            .clientId(clientId)
            .sdkInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression("#p = :p")
                .filterExpression("#fl = :v")
                .expressionAttributeNames(Map.of("#p", PK, "#fl", COMPOUND_NAME))
                .expressionAttributeValues(Map.of(
                    ":p", AttributeValue.builder().s("item-1").build(),
                    ":v", AttributeValue.builder().s("F-john.L-doe").build()))
                .build())
            .build()).getTransformedInput();

        assertEquals("aws_dbe_b_" + COMPOUND_NAME,
            transformed.getExpressionAttributeNames().get("#fl"),
            "the compound-beacon filter attribute must be rewritten to its beacon on " + pair);
        assertEquals(PK, transformed.getExpressionAttributeNames().get("#p"),
            "the non-beaconed partition key must be left unchanged on " + pair);
        assertNotEquals("F-john.L-doe",
            transformed.getExpressionAttributeValues().get(":v").getS(),
            "the compound value's encrypted parts must be beaconized on " + pair);
    }

    @ParameterizedTest(name = "[beacon] a compound-part value containing the split char is rejected on write {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundPartValueContainingSplitCharRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // Single defect on the proven-valid compound config (COMPOUND_NAME, split
        // "."): `first`'s plaintext value "a.b" contains the split character, so
        // the write-path compound-beacon construction cannot be assembled and
        // PutItemInputTransform fails. Everything else is the config the
        // round-trip and rewrite tests already prove valid.
        String clientId = createBeaconClient(client, compoundBeaconSearch(), beaconActions());

        //= specification/searchable-encryption/beacons.md#value-for-a-compound-beacon
        //= type=test
        //# This operation MUST fail if any plaintext value used in the construction contains the split character.
        assertThrows(DBESDKTestServerException.class,
            () -> encryptCompoundItem(client, clientId, "item-1", "a.b", "doe"),
            "a compound-part value containing the split character must be rejected on write on "
                + pair);
    }

    @ParameterizedTest(name = "[beacon] QueryInputTransform rejects a compound value with no constructor {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconQueryValueWithNoConstructorRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconClient(client, compoundBeaconSearch(), beaconActions());

        // The compound COMPOUND_NAME has a single constructor: an F- part
        // (first) then an L- part (last). "F-john.F-jane" parses as two F- parts,
        // which no constructor can build, so beaconizing the query value fails.
        // Single defect on the proven-valid compound config — the same config
        // that queryInputTransformRewritesCompoundBeaconFilter accepts "F-john.L-doe" against.
        // Dafny Beacon.dfy TestCompoundQueries: "N_MyName.N_MyName" (parsed as
        // N_N_) "cannot be constructed from any available constructor for Mixed".
        assertThrows(DBESDKTestServerException.class,
            () -> client.queryInputTransform(QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#fl = :v")
                    .expressionAttributeNames(Map.of("#p", PK, "#fl", COMPOUND_NAME))
                    .expressionAttributeValues(Map.of(
                        ":p", AttributeValue.builder().s("item-1").build(),
                        ":v", AttributeValue.builder().s("F-john.F-jane").build()))
                    .build())
                .build()),
            "a compound query value matching no constructor must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] AsSet beacon query value is beaconized element-wise; a non-Set value is rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void asSetBeaconQueryValueBeaconizedAndWrongTypeRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // A single AsSet standard beacon over a Set attribute.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(TAGS).length(10)
                .style(BeaconStyle.builder().asSet(AsSet.builder().build()).build())
                .build())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(TAGS, CryptoAction.ENCRYPT_AND_SIGN);
        String clientId = createBeaconClient(client, search, actions);

        // An SS query value is beaconized element-wise: the filter attribute is
        // rewritten to its beacon, and each element is replaced by its own beacon
        // value (still an SS, one beacon per element, none equal to plaintext).
        // Dafny Beacon.dfy TestBeaconSetQuery: SS(["abc","def","ghi"]) rewrites to
        // SS(["43c4d8","2f3278","f1972e"]) (the hashes are keyed on the live store).
        List<String> elements = List.of("abc", "def", "ghi");
        QueryInput rewritten = client.queryInputTransform(QueryInputTransformInput.builder()
            .clientId(clientId)
            .sdkInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression("#p = :p")
                .filterExpression("#t = :v")
                .expressionAttributeNames(Map.of("#p", PK, "#t", TAGS))
                .expressionAttributeValues(Map.of(
                    ":p", AttributeValue.builder().s("item-1").build(),
                    ":v", AttributeValue.builder().ss(elements).build()))
                .build())
            .build()).getTransformedInput();

        assertEquals("aws_dbe_b_" + TAGS, rewritten.getExpressionAttributeNames().get("#t"),
            "the AsSet beacon attribute name must be rewritten to its beacon on " + pair);
        AttributeValue rewrittenValue = rewritten.getExpressionAttributeValues().get(":v");
        assertNotNull(rewrittenValue.getSs(),
            "an AsSet query value must remain a String Set after beaconization on " + pair);
        assertEquals(elements.size(), rewrittenValue.getSs().size(),
            "each Set element must be beaconized to its own value on " + pair);
        assertNotEquals(
            new java.util.HashSet<>(elements), new java.util.HashSet<>(rewrittenValue.getSs()),
            "the AsSet query elements must be beaconized (changed) on " + pair);

        // A non-Set (L-typed) value for an AsSet beacon is rejected: the same
        // proven-valid config, the single defect being the value's type.
        // Dafny Beacon.dfy TestBeaconSetQuery: L([]) -> "Beacon setAttr has style
        // AsSet, but attribute has type L."
        assertThrows(DBESDKTestServerException.class,
            () -> client.queryInputTransform(QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(QueryInput.builder()
                    .tableName(TABLE)
                    .keyConditionExpression("#p = :p")
                    .filterExpression("#t = :v")
                    .expressionAttributeNames(Map.of("#p", PK, "#t", TAGS))
                    .expressionAttributeValues(Map.of(
                        ":p", AttributeValue.builder().s("item-1").build(),
                        ":v", AttributeValue.builder().l(List.of()).build()))
                    .build())
                .build()),
            "a non-Set (L) value for an AsSet beacon must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] numerically-equal N values produce the same beacon {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void numericallyEqualValuesProduceEqualBeacon(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // A standard beacon over an encrypted Number attribute. DBE normalizes a
        // Number to a single canonical form before beaconizing, so two
        // numerically-equal but differently-written N values must beaconize to the
        // SAME value (a value oracle, not a bare throws).
        // Dafny Beacon.dfy TestNumbersNormalize: N("1.23") and N("000001.23000000")
        // yield the same aws_dbe_b_std2.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder().name(SCORE).length(10).build())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(SCORE, CryptoAction.ENCRYPT_AND_SIGN);
        String clientId = createBeaconClient(client, search, actions);
        String beaconAttr = "aws_dbe_b_" + SCORE;

        Map<String, AttributeValue> canonical = new LinkedHashMap<>();
        canonical.put(PK, AttributeValue.builder().s("item-1").build());
        canonical.put(SCORE, AttributeValue.builder().n("1.23").build());
        Map<String, AttributeValue> equivalent = new LinkedHashMap<>();
        equivalent.put(PK, AttributeValue.builder().s("item-1").build());
        equivalent.put(SCORE, AttributeValue.builder().n("000001.23000000").build());

        AttributeValue canonicalBeacon =
            encryptAndGetBeacon(client, clientId, canonical, beaconAttr, pair);
        AttributeValue equivalentBeacon =
            encryptAndGetBeacon(client, clientId, equivalent, beaconAttr, pair);

        assertEquals(canonicalBeacon, equivalentBeacon,
            "numerically-equal N values must produce the same beacon on " + pair);
    }

    @ParameterizedTest(name = "[beacon] compound beacon re-filters begins_with {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconReFiltersBeginsWith(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconClient(client, compoundBeaconSearch(), beaconActions());

        // Unlike a standard (equality-only) beacon, a compound beacon supports a
        // prefix (begins_with) query on the assembled "F-<first>.L-<last>" value.
        // The server-side beacon prefix is imprecise, so ScanOutputTransform
        // re-applies begins_with on the reconstructed plaintext compound and drops
        // the non-matching item.
        Map<String, AttributeValue> matching = encryptCompoundItem(client, clientId, "item-john", "john", "doe");
        Map<String, AttributeValue> other = encryptCompoundItem(client, clientId, "item-jane", "jane", "doe");

        ScanOutput out = client.scanOutputTransform(ScanOutputTransformInput.builder()
            .clientId(clientId)
            .originalInput(ScanInput.builder()
                .tableName(TABLE)
                .filterExpression("begins_with(#fl, :p)")
                .expressionAttributeNames(Map.of("#fl", COMPOUND_NAME))
                .expressionAttributeValues(Map.of(":p",
                    AttributeValue.builder().s("F-john").build()))
                .build())
            .sdkOutput(ScanOutput.builder().items(List.of(matching, other)).build())
            .build()).getTransformedOutput();

        assertNotNull(out.getItems(), "ScanOutputTransform returned no items on " + pair);
        assertEquals(1, out.getItems().size(),
            "compound begins_with re-filter must drop the non-matching item on " + pair);
        assertEquals("john", out.getItems().get(0).get(FIRST).getS(),
            "the surviving item must be the one whose compound value begins with the prefix on "
                + pair);
    }

    @ParameterizedTest(name = "[beacon] QueryOutputTransform re-filters a compound begins_with {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryCompoundBeaconReFiltersBeginsWith(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconClient(client, compoundBeaconSearch(), beaconActions());

        // The compound begins_with re-filter also fires on the Query path. Both
        // items share a partition key so the (non-beaconed) key condition does not
        // distinguish them — only the compound begins_with does.
        Map<String, AttributeValue> matching = encryptCompoundItem(client, clientId, "item-1", "john", "doe");
        Map<String, AttributeValue> other = encryptCompoundItem(client, clientId, "item-1", "jane", "doe");

        QueryOutput out = client.queryOutputTransform(QueryOutputTransformInput.builder()
            .clientId(clientId)
            .originalInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression("#p = :p")
                .filterExpression("begins_with(#fl, :prefix)")
                .expressionAttributeNames(Map.of("#p", PK, "#fl", COMPOUND_NAME))
                .expressionAttributeValues(Map.of(
                    ":p", AttributeValue.builder().s("item-1").build(),
                    ":prefix", AttributeValue.builder().s("F-john").build()))
                .build())
            .sdkOutput(QueryOutput.builder().items(List.of(matching, other)).build())
            .build()).getTransformedOutput();

        assertNotNull(out.getItems(), "QueryOutputTransform returned no items on " + pair);
        assertEquals(1, out.getItems().size(),
            "Query compound begins_with re-filter must drop the non-matching item on " + pair);
        assertEquals("john", out.getItems().get(0).get(FIRST).getS(),
            "the surviving item must be the one whose compound value begins with the prefix on "
                + pair);
    }

    /** Encrypt an item ({@code pk}, {@code first}, {@code last}) through the beacon write path. */
    private static Map<String, AttributeValue> encryptCompoundItem(
            DBESDKTestServerClient client, String clientId, String pk, String first, String last) {
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s(pk).build());
        item.put(FIRST, AttributeValue.builder().s(first).build());
        item.put(LAST, AttributeValue.builder().s(last).build());
        return client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build()).getTransformedInput().getItem();
    }

    @ParameterizedTest(name = "[beacon] signed compound beacon re-filters BETWEEN {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void signedCompoundBeaconReFiltersBetween(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = createBeaconClient(client, signedCompoundBeaconSearch(), signedPartActions());

        // The compound is a single SIGNED part "L-<last>" (plaintext, order-
        // preserving). Its two BETWEEN bounds are LessThanComparable, so DBE
        // permits BETWEEN and ScanOutputTransform re-applies it: last in [a, m]
        // survives, "zed" drops. (A standard beacon rejects BETWEEN outright.)
        Map<String, AttributeValue> inRange = encryptCompoundItem(client, clientId, "item-bob", "x", "bob");
        Map<String, AttributeValue> outOfRange = encryptCompoundItem(client, clientId, "item-zed", "x", "zed");

        ScanOutput out = client.scanOutputTransform(ScanOutputTransformInput.builder()
            .clientId(clientId)
            .originalInput(ScanInput.builder()
                .tableName(TABLE)
                .filterExpression("#c BETWEEN :lo AND :hi")
                .expressionAttributeNames(Map.of("#c", SIGNED_COMPOUND_NAME))
                .expressionAttributeValues(Map.of(
                    ":lo", AttributeValue.builder().s("L-a").build(),
                    ":hi", AttributeValue.builder().s("L-m").build()))
                .build())
            .sdkOutput(ScanOutput.builder().items(List.of(inRange, outOfRange)).build())
            .build()).getTransformedOutput();

        assertNotNull(out.getItems(), "ScanOutputTransform returned no items on " + pair);
        assertEquals(1, out.getItems().size(),
            "signed-compound BETWEEN re-filter must drop the out-of-range item on " + pair);
        assertEquals("bob", out.getItems().get(0).get(LAST).getS(),
            "the surviving item must be the one whose signed part is within the range on " + pair);
    }

    private static SearchConfig signedCompoundBeaconSearch() {
        return beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name(SIGNED_COMPOUND_NAME)
                .split(".")
                .signed(List.of(SignedPart.builder().name(LAST).prefix("L-").build()))
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));
    }

    @ParameterizedTest(name = "[beacon] BETWEEN over a non-LessThanComparable compound part is rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconBetweenNonComparableRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // The Dafny NameTitle analog: two ENCRYPTED parts (F-<first>.L-<last>),
        // default constructor. Encrypted parts are equality-only (hashed), i.e.
        // NOT LessThanComparable — the property this test exercises.
        String clientId = createBeaconClient(client, defaultConstructorCompoundBeaconSearch(), beaconActions());

        // Control: an equality query on the full compound is valid and beaconizes,
        // proving the config and the query path are sound — so the rejection below
        // isolates a single defect (the BETWEEN operator), not a broken config.
        // Dafny FilterExpr.dfy TestFilterBeacons: `NameTitle = "N_MyName.T_MyTitle"`
        // succeeds and each encrypted part is beaconized.
        QueryInput control = beaconQuery(client, clientId, "#c = :v",
            Map.of(":v", AttributeValue.builder().s("F-john.L-doe").build()));
        assertEquals("aws_dbe_b_" + COMPOUND_NAME, control.getExpressionAttributeNames().get("#c"),
            "the control equality query must rewrite the compound attribute to its beacon on " + pair);
        assertNotEquals("F-john.L-doe", control.getExpressionAttributeValues().get(":v").getS(),
            "the control equality value's encrypted parts must be beaconized on " + pair);

        // Defect: the BETWEEN bounds share the F-john part and differ only in the
        // encrypted L-(last) part, so `last` is the part after the common prefix
        // and it is NOT LessThanComparable — QueryInputTransform must reject it.
        // Dafny FilterExpr.dfy TestBadBetween: `NameTitle between "T_ATitle" and
        // "T_MyTitle"` fails with (byte-exact error string):
        //   "To use BETWEEN with a compound beacon, the part after any common prefix
        //    must be LessThanComparable : BETWEEN T_ATitle AND T_MyTitle"
        assertThrows(DBESDKTestServerException.class,
            () -> beaconQuery(client, clientId, "#c BETWEEN :lo AND :hi",
                Map.of(
                    ":lo", AttributeValue.builder().s("F-john.L-a").build(),
                    ":hi", AttributeValue.builder().s("F-john.L-m").build())),
            "BETWEEN over a non-LessThanComparable (encrypted) compound part must be rejected on "
                + pair);
    }

    @ParameterizedTest(name = "[beacon] compound-beacon =/</BETWEEN comparability semantics {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconComparisonSemantics(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        // The Dafny NameTitle analog (two ENCRYPTED parts, default constructor):
        // N_<Name>.T_<Title> maps to F-<first>.L-<last>. The default constructor
        // permits the part-prefix queries TestComparisons exercises.
        String clientId = createBeaconClient(client, defaultConstructorCompoundBeaconSearch(), beaconActions());

        // (A) `=` on a bare part prefix (the empty `first` value "F-") succeeds and
        //     BEACONIZES the empty value: the rewritten value keeps the prefix but
        //     is no longer the bare "F-". Dafny FilterExpr.dfy TestComparisons:
        //     `NameTitle = :val1` (val1 = "N_") rewrites :val1 to DS("N_" + EmptyName_beacon).
        QueryInput eq = beaconQuery(client, clientId, "#c = :v",
            Map.of(":v", AttributeValue.builder().s("F-").build()));
        assertEquals("aws_dbe_b_" + COMPOUND_NAME, eq.getExpressionAttributeNames().get("#c"),
            "`=` must rewrite the compound attribute to its beacon on " + pair);
        String eqValue = eq.getExpressionAttributeValues().get(":v").getS();
        assertTrue(eqValue.startsWith("F-"),
            "the beaconized equality value must keep the part prefix on " + pair);
        assertNotEquals("F-", eqValue,
            "`=` must beaconize the (empty) part value onto the prefix on " + pair);

        // (B) `<` on the SAME bare part prefix succeeds but leaves the prefix BARE
        //     (the comparable prefix, un-beaconized). Dafny FilterExpr.dfy
        //     TestComparisons: `NameTitle < :val1` rewrites :val1 to DS("N_").
        QueryInput lt = beaconQuery(client, clientId, "#c < :v",
            Map.of(":v", AttributeValue.builder().s("F-").build()));
        assertEquals("aws_dbe_b_" + COMPOUND_NAME, lt.getExpressionAttributeNames().get("#c"),
            "`<` must rewrite the compound attribute to its beacon on " + pair);
        assertEquals("F-", lt.getExpressionAttributeValues().get(":v").getS(),
            "`<` on a compound must truncate to the bare comparable prefix (no beacon) on " + pair);

        // (C) `=` on a part VALUE ("first" = "john") succeeds and beaconizes.
        //     Dafny FilterExpr.dfy TestComparisons: `NameTitle = :val2`
        //     (val2 = "N_MyName") → Success.
        QueryInput eqValueQuery = beaconQuery(client, clientId, "#c = :v",
            Map.of(":v", AttributeValue.builder().s("F-john").build()));
        assertEquals("aws_dbe_b_" + COMPOUND_NAME, eqValueQuery.getExpressionAttributeNames().get("#c"),
            "`=` on a part value must rewrite the compound attribute to its beacon on " + pair);
        assertNotEquals("F-john", eqValueQuery.getExpressionAttributeValues().get(":v").getS(),
            "`=` on a part value must beaconize it on " + pair);

        // (D) `<` on a part VALUE fails: `first` is an ENCRYPTED (equality-only)
        //     beacon, not LessThanComparable. Dafny FilterExpr.dfy TestComparisons:
        //     `NameTitle < :val2` (val2 = "N_MyName") → Failure.
        assertThrows(DBESDKTestServerException.class,
            () -> beaconQuery(client, clientId, "#c < :v",
                Map.of(":v", AttributeValue.builder().s("F-john").build())),
            "`<` on an encrypted (non-LessThanComparable) part value must be rejected on " + pair);

        // (E) BETWEEN whose bounds differ in an encrypted part VALUE (empty vs
        //     "john") fails for the same reason as (D). Dafny FilterExpr.dfy
        //     TestComparisons: `NameTitle between :val1 and :val2`
        //     (val1 = "N_", val2 = "N_MyName") → Failure.
        assertThrows(DBESDKTestServerException.class,
            () -> beaconQuery(client, clientId, "#c BETWEEN :lo AND :hi",
                Map.of(
                    ":lo", AttributeValue.builder().s("F-").build(),
                    ":hi", AttributeValue.builder().s("F-john").build())),
            "BETWEEN over an encrypted part value must be rejected on " + pair);
    }

    /**
     * A faithful analog of the Dafny {@code NameTitle} compound beacon used by
     * {@code FilterExpr.dfy} {@code TestBadBetween} / {@code TestComparisons}: two
     * ENCRYPTED parts ({@code F-<first>.L-<last>}) with the default constructor
     * ({@code constructors := None}), which permits the part-prefix queries those
     * methods exercise. Encrypted parts are hashed (equality-only), so neither is
     * LessThanComparable — the property under test.
     */
    private static SearchConfig defaultConstructorCompoundBeaconSearch() {
        return beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name(COMPOUND_NAME)
                .split(".")
                .encrypted(List.of(
                    EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                    EncryptedPart.builder().name(LAST).prefix("L-").build()))
                .build())));
    }

    /**
     * Run a compound-beacon filter through QueryInputTransform against a fixed
     * (non-beaconed) partition key, and return the transformed input. The compound
     * attribute is referenced as {@code #c}; callers supply the filter expression
     * and its value placeholders (e.g. {@code :v}, or {@code :lo}/{@code :hi} for
     * BETWEEN). Only the names/values actually referenced are sent.
     */
    private static QueryInput beaconQuery(
            DBESDKTestServerClient client, String clientId,
            String filterExpression, Map<String, AttributeValue> filterValues) {
        Map<String, String> names = new LinkedHashMap<>();
        names.put("#p", PK);
        names.put("#c", COMPOUND_NAME);
        Map<String, AttributeValue> values = new LinkedHashMap<>();
        values.put(":p", AttributeValue.builder().s("item-1").build());
        values.putAll(filterValues);
        return client.queryInputTransform(QueryInputTransformInput.builder()
            .clientId(clientId)
            .sdkInput(QueryInput.builder()
                .tableName(TABLE)
                .keyConditionExpression("#p = :p")
                .filterExpression(filterExpression)
                .expressionAttributeNames(names)
                .expressionAttributeValues(values)
                .build())
            .build()).getTransformedInput();
    }

    @ParameterizedTest(name = "[beacon] Upper virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void upperVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Upper("john") -> "JOHN": changes the virtual-field input, so a different beacon.
        //= specification/searchable-encryption/virtual.md#upper-transform-initialization
        //= type=test
        //= reason=Upper("john")->"JOHN" changes the virtual-field input, so the beacon differs from untransformed
        //# The Upper transform MUST convert all ascii lowercase characters into their uppercase equivalents.
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder().upper(Upper.builder().build()).build(),
            beaconPlaintext(), "Upper");
    }

    @ParameterizedTest(name = "[beacon] Lower virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void lowerVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Lower needs an upper-case input to have an effect: Lower("JOHN") -> "john".
        //= specification/searchable-encryption/virtual.md#lower-transform-initialization
        //= type=test
        //= reason=Lower("JOHN")->"john" changes the virtual-field input, so the beacon differs from untransformed
        //# The Lower transform MUST convert all ascii uppercase characters into their lowercase equivalents.
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder().lower(Lower.builder().build()).build(),
            beaconPlaintextWithFirst("JOHN"), "Lower");
    }

    @ParameterizedTest(name = "[beacon] Insert virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void insertVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Insert appends a literal: "john" -> "john-x".
        //= specification/searchable-encryption/virtual.md#insert-transform-initialization
        //= type=test
        //= reason=Insert appends "-x" to the virtual-field input, so the beacon differs from untransformed
        //# The Insert transform MUST append this string to its input
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder().insert(Insert.builder().literal("-x").build()).build(),
            beaconPlaintext(), "Insert");
    }

    @ParameterizedTest(name = "[beacon] GetSubstring virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void substringVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // GetSubstring(0, 2) keeps the first two characters: "john" -> "jo".
        //= specification/searchable-encryption/virtual.md#getsubstring-transform-initialization
        //= type=test
        //= reason=GetSubstring(0,2) keeps "jo" of the virtual-field input, so the beacon differs from untransformed
        //# The GetSubstring transform MUST return the range of characters
        //# from low (inclusive) to high (exclusive)
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder().substring(GetSubstring.builder().low(0).high(2).build()).build(),
            beaconPlaintext(), "GetSubstring");
    }

    @ParameterizedTest(name = "[beacon] GetSegment virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void segmentVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Split "a.b.c" on "." and take segment 1: "a.b.c" -> "b".
        //= specification/searchable-encryption/virtual.md#getsegment-transform-initialization
        //= type=test
        //= reason=GetSegment(".",1) yields "b" from "a.b.c", so the beacon differs from untransformed
        //# The GetSegment transform MUST split the input string on the given character,
        //# and return the item in the resulting list the corresponds to the given position.
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder()
                .segment(GetSegment.builder().split(".").index(1).build()).build(),
            beaconPlaintextWithFirst("a.b.c"), "GetSegment");
    }

    @ParameterizedTest(name = "[beacon] GetSegments virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void segmentsVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Split "a.b.c" on "." and take the [0, 2) segment range: "a.b.c" -> "a.b".
        //= specification/searchable-encryption/virtual.md#getsegments-transform-initialization
        //= type=test
        //= reason=GetSegments(".",0,2) yields "a.b" from "a.b.c", so the beacon differs from untransformed
        //# GetSegments MUST return the range of parts from low (inclusive) to high (exclusive),
        //# joined on the `split` character.
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder()
                .segments(GetSegments.builder().split(".").low(0).high(2).build()).build(),
            beaconPlaintextWithFirst("a.b.c"), "GetSegments");
    }

    @ParameterizedTest(name = "[beacon] GetPrefix virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void prefixVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // GetPrefix(3) keeps the first three characters: "john" -> "joh".
        //= specification/searchable-encryption/virtual.md#getprefix-transform-initialization
        //= type=test
        //= reason=GetPrefix(3) keeps "joh" of the virtual-field input, so the beacon differs from untransformed
        //# If length is non-negative, the GetPrefix transform MUST return the first `length` characters of the input.
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder().prefix(GetPrefix.builder().length(3).build()).build(),
            beaconPlaintext(), "GetPrefix");
    }

    @ParameterizedTest(name = "[beacon] GetSuffix virtual-part transform changes the beacon value {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void suffixVirtualPartTransformChangesTheBeaconValue(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // GetSuffix(2) keeps the last two characters: "john" -> "hn".
        //= specification/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //= type=test
        //= reason=GetSuffix(2) keeps "hn" of the virtual-field input, so the beacon differs from untransformed
        //# If length is non-negative, the GetSuffix transform MUST return the last `length` characters of the input.
        assertVirtualTransformChangesBeacon(pair,
            VirtualTransform.builder().suffix(GetSuffix.builder().length(2).build()).build(),
            beaconPlaintext(), "GetSuffix");
    }

    /**
     * Encrypt {@code plaintext} under a {@code fullName} virtual field with no
     * transform and under one applying {@code firstTransform} to the {@code first}
     * part. Beacons are deterministic, so the two untransformed encrypts must
     * produce the SAME beacon (the control that makes the comparison value-based),
     * and the transformed config must produce a DIFFERENT beacon — proving the
     * transform is actually applied rather than silently ignored.
     */
    private void assertVirtualTransformChangesBeacon(
            TargetPair pair, VirtualTransform firstTransform,
            Map<String, AttributeValue> plaintext, String label) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String plainId = createBeaconClient(client, virtualFieldSearch(null), beaconActions());
        String transformedId =
            createBeaconClient(client, virtualFieldSearch(firstTransform), beaconActions());
        String beaconAttr = "aws_dbe_b_" + VIRTUAL_NAME;

        AttributeValue plain1 = encryptAndGetBeacon(client, plainId, plaintext, beaconAttr, pair);
        AttributeValue plain2 = encryptAndGetBeacon(client, plainId, plaintext, beaconAttr, pair);
        AttributeValue transformed =
            encryptAndGetBeacon(client, transformedId, plaintext, beaconAttr, pair);

        assertEquals(plain1, plain2,
            "an untransformed virtual-field beacon must be deterministic (control) on " + pair);
        assertNotEquals(plain1, transformed,
            "the " + label + " transform must change the virtual-field beacon on " + pair);
    }

    /** Encrypt the given plaintext and return the written beacon attribute value. */
    private static AttributeValue encryptAndGetBeacon(
            DBESDKTestServerClient client, String clientId,
            Map<String, AttributeValue> plaintext, String beaconAttr, TargetPair pair) {
        Map<String, AttributeValue> encrypted = client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(plaintext).build())
                .build()).getTransformedInput().getItem();
        AttributeValue beacon = encrypted.get(beaconAttr);
        assertNotNull(beacon, "beacon '" + beaconAttr + "' must be written on " + pair);
        return beacon;
    }

    /**
     * A SearchConfig with a standard beacon over a {@code fullName} virtual field
     * (first + last). When {@code firstTransform} is non-null it is applied to the
     * {@code first} part.
     */
    private static SearchConfig virtualFieldSearch(VirtualTransform firstTransform) {
        VirtualPart.Builder firstPart = VirtualPart.builder().loc(FIRST);
        if (firstTransform != null) {
            firstPart.trans(List.of(firstTransform));
        }
        return beaconSearch(BeaconVersion.builder()
            .virtualFields(List.of(VirtualField.builder()
                .name(VIRTUAL_NAME)
                .parts(List.of(firstPart.build(), VirtualPart.builder().loc(LAST).build()))
                .build()))
            .standardBeacons(List.of(
                StandardBeacon.builder().name(VIRTUAL_NAME).length(10).build())));
    }

    /** The beacon plaintext with the {@code first} attribute set to {@code firstValue}. */
    private static Map<String, AttributeValue> beaconPlaintextWithFirst(String firstValue) {
        Map<String, AttributeValue> item = beaconPlaintext();
        item.put(FIRST, AttributeValue.builder().s(firstValue).build());
        return item;
    }

    /**
     * A SearchConfig whose beacon version carries the {@link #COMPOUND_NAME}
     * compound beacon (two encrypted parts, {@code F-<first>.L-<last>}) — the
     * same configuration proven by {@link #compoundBeaconWrittenAndItemRoundTrips}.
     */
    private static SearchConfig compoundBeaconSearch() {
        return beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name(COMPOUND_NAME)
                .split(".")
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));
    }

    /**
     * Encrypt the beacon plaintext on the pair's encrypt endpoint via
     * PutItemInputTransform, assert {@code beaconAttr} was written, then decrypt
     * on the decrypt endpoint via GetItemOutputTransform and assert every source
     * attribute round-trips and the beacon attribute is stripped.
     */
    private void assertBeaconWrittenAndRoundTrips(
            TargetPair pair, SearchConfig search, String beaconAttr,
            Map<String, CryptoAction> actions) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = beaconPlaintext();

        String encryptClientId = createBeaconClient(encryptClient, search, actions);
        Map<String, AttributeValue> encrypted = encryptClient.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(encryptClientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(plaintext).build())
                .build()).getTransformedInput().getItem();

        assertTrue(encrypted.containsKey(beaconAttr),
            "beacon attribute '" + beaconAttr + "' must be written on encrypt on " + pair);

        String decryptClientId = createBeaconClient(decryptClient, search, actions);
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
        assertFalse(recovered.containsKey(beaconAttr),
            "beacon attribute must be stripped from the decrypted item on " + pair);
    }

    /** The beacon-test schema: PK plus two ENCRYPT_AND_SIGN attributes. */
    private static Map<String, CryptoAction> beaconActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        return actions;
    }

    /**
     * Schema for the signed-part compound beacon: {@code first} is
     * {@code ENCRYPT_AND_SIGN} (its standard beacon backs the encrypted part),
     * while {@code last} is {@code SIGN_ONLY} — a signed, non-encrypted attribute
     * a signed part may reference (an {@code ENCRYPT_AND_SIGN} attribute would
     * have to be an encrypted part instead).
     */
    private static Map<String, CryptoAction> signedPartActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.SIGN_ONLY);
        return actions;
    }

    /** Deterministic plaintext for the beacon-test schema. */
    private static Map<String, AttributeValue> beaconPlaintext() {
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(FIRST, AttributeValue.builder().s("john").build());
        item.put(LAST, AttributeValue.builder().s("doe").build());
        return item;
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
