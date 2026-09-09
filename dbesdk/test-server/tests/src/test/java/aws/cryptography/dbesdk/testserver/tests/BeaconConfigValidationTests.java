package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
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
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for beacon config-validation (§0.3.6): an invalid
 * searchable-encryption configuration must be rejected when the transforms
 * client is created, before any item is written.
 *
 * <p>The bounded property: {@code CreateTransformsClient} fails (surfacing as a
 * {@link DBESDKTestServerException}) when the beacon configuration violates a
 * construct-time invariant. Each case is a single invalid mutation of an
 * otherwise-valid config (the valid form is proven by
 * {@link CompoundAndVirtualBeaconTests}), so the rejection is attributable to
 * the intended defect rather than an unrelated one.
 *
 * <p>The three invariants, grounded in the DBE library's {@code ConfigToInfo}
 * validation:
 * <ul>
 *   <li>A standard beacon may only be built over an {@code ENCRYPT_AND_SIGN}
 *       attribute — beaconing a signed-but-unencrypted attribute is rejected
 *       ("already an unencrypted attribute").</li>
 *   <li>A compound beacon's encrypted part must reference a configured standard
 *       beacon ("refers to standard beacon ... which is not configured").</li>
 *   <li>The parts of a compound beacon must have distinct prefixes ("Duplicate
 *       prefix ...").</li>
 * </ul>
 *
 * <p>Validation is construct-time (it precedes any beacon-key fetch), but the
 * config still names the live key store so construction reaches the beacon
 * validation. Each CreateTransformsClient runs on the pair's encrypt endpoint,
 * so across the matrix every language server validates.
 */
class BeaconConfigValidationTests {

    // Live beacon key store resources (resource identifiers, not secrets).
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";

    private static final String FIRST = "first";
    private static final String LAST = "last";

    @ParameterizedTest(name = "[beacon] standard beacon over non-encrypted attribute rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void standardBeaconOverNonEncryptedAttributeIsRejected(TargetPair pair) {
        // `public` is SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT (signed, not
        // encrypted); a standard beacon may only cover an ENCRYPT_AND_SIGN attr.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(PUBLIC).length(10).build())));

        //= specification/searchable-encryption/search-config.md#beacon-version-initialization
        //= type=test
        //# Initialization MUST fail if the [terminal location](virtual.md#terminal-location)
        //# reference by a [standard beacon](beacons.md#standard-beacon) is not `encrypted`.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, standardActions(), search),
            "a standard beacon over the non-encrypted attribute '" + PUBLIC
                + "' must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] compound part referencing unconfigured beacon rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconWithUnconfiguredEncryptedPartIsRejected(TargetPair pair) {
        // `ghost` is used as an encrypted part but has no standard beacon.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name("ghost").prefix("G-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("firstGhost")
                .split(".")
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name("ghost").required(true).build()))
                    .build()))
                .build())));

        //= specification/searchable-encryption/beacons.md#compound-beacon
        //= type=test
        //# The name MUST be the name of a configured standard beacon.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a compound beacon whose encrypted part references an unconfigured standard"
                + " beacon must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] compound with duplicate prefix rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconWithDuplicatePrefixIsRejected(TargetPair pair) {
        // Both encrypted parts share the prefix "P-".
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("P-").build(),
                EncryptedPart.builder().name(LAST).prefix("P-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("firstLast")
                .split(".")
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));

        //= specification/searchable-encryption/beacons.md#initialization-failure
        //= type=test
        //# Initialization MUST fail if any `prefix` in any [part](#part) is a prefix of
        //# the `prefix` of any other [part](#part).
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a compound beacon with duplicate part prefixes must be rejected on " + pair);
    }

    /** Two ENCRYPT_AND_SIGN attributes plus the partition key. */
    private static Map<String, CryptoAction> beaconActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        return actions;
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

    private static void createBeaconClient(
            TargetPair pair, Map<String, CryptoAction> actions, SearchConfig search) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
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
        client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(TABLE).build());
    }
}
