package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import aws.cryptography.dbesdk.testserver.client.model.EncryptedPart;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SignedPart;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.dbesdk.testserver.client.model.VirtualField;
import aws.cryptography.dbesdk.testserver.client.model.VirtualPart;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for compound and virtual-field beacons (§0.3.6),
 * building on the standard-beacon configuration proven by {@link BeaconConfigTests}.
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
class CompoundAndVirtualBeaconTests {

    // Live beacon key store resources (resource identifiers, not secrets;
    // access is gated by AWS credentials) — same store as BeaconConfigTests.
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

    @ParameterizedTest(name = "[beacon] compound beacon written + round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconWrittenAndItemRoundTrips(TargetPair pair) {
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
