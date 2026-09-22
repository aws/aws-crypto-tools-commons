package aws.cryptography.dbesdk.testserver.tests.search;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.AsSet;
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
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PartOnly;
import aws.cryptography.dbesdk.testserver.client.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.client.model.Shared;
import aws.cryptography.dbesdk.testserver.client.model.SignedPart;
import aws.cryptography.dbesdk.testserver.client.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.client.model.StandardBeacon;
import aws.cryptography.dbesdk.testserver.client.model.VirtualField;
import aws.cryptography.dbesdk.testserver.client.model.VirtualPart;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for beacon config-validation: an invalid
 * searchable-encryption configuration must be rejected when the transforms
 * client is created, before any item is written.
 *
 * <p>The bounded property: {@code CreateTransformsClient} fails (surfacing as a
 * {@link DBESDKTestServerException}) when the beacon configuration violates a
 * construct-time invariant. Each case is a single invalid mutation of an
 * otherwise-valid config (the valid form is proven by
 * {@link CompoundAndVirtualSearchMetadataTests}), so the rejection is attributable to
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
class SearchConfigurationValidationTests {

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
        FeatureGate.require(Set.of("searchable-encryption"), pair);
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
        FeatureGate.require(Set.of("searchable-encryption"), pair);
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
        FeatureGate.require(Set.of("searchable-encryption"), pair);
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

    @ParameterizedTest(name = "[beacon] two standard beacons on same location rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void twoStandardBeaconsOnSameLocationRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Two beacons both calculate over location `first`.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name("firstAlias").length(10).loc(FIRST).build())));

        //= specification/searchable-encryption/beacons.md#standard-beacon-initialization
        //= type=test
        //# Initialization MUST fail if two standard beacons are configured with the same location.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "two standard beacons on the same location must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] PartOnly beacon not used in a compound rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void partOnlyBeaconNotUsedInCompoundRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // A PartOnly beacon with no compound beacon consuming it.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(FIRST).length(10)
                .style(BeaconStyle.builder().partOnly(PartOnly.builder().build()).build())
                .build())));

        //= specification/searchable-encryption/beacons.md#partonly-initialization
        //= type=test
        //# Initialization MUST fail if the configuration does not use a PartOnly in a [compound beacon](#compound-beacon).
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a PartOnly beacon unused in any compound must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] AsSet beacon used in a compound rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void asSetBeaconUsedInCompoundRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // `first` is an AsSet beacon, then used as an encrypted part of a compound.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10)
                    .style(BeaconStyle.builder().asSet(AsSet.builder().build()).build())
                    .build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("firstLast")
                .split(".")
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));

        //= specification/searchable-encryption/beacons.md#asset-initialization
        //= type=test
        //# - initialization MUST fail if any compound beacon has an AsSet beacon as a part.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "an AsSet beacon used inside a compound beacon must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] shared beacon referencing an undefined beacon rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void sharedBeaconReferencingUndefinedRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // `first` is Shared to a beacon `nope` that is never defined.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(FIRST).length(10)
                .style(BeaconStyle.builder().shared(Shared.builder().other("nope").build()).build())
                .build())));

        //= specification/searchable-encryption/beacons.md#shared-initialization
        //= type=test
        //# This name MUST be the name of a previously defined Standard Beacon.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a Shared beacon referencing an undefined beacon must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] shared beacon to itself rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void sharedBeaconToItselfRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // `first` is Shared to itself — not a *previously defined* beacon.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder()
                .name(FIRST).length(10)
                .style(BeaconStyle.builder().shared(Shared.builder().other(FIRST).build()).build())
                .build())));

        //= specification/searchable-encryption/beacons.md#shared-initialization
        //= type=test
        //# This name MUST be the name of a previously defined Standard Beacon.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a Shared beacon referencing itself must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] shared beacon length mismatch rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void sharedBeaconLengthMismatchRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // `first` is Shared to `last` but declares a different length (24 vs 10).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(LAST).length(10).build(),
                StandardBeacon.builder().name(FIRST).length(24)
                    .style(BeaconStyle.builder().shared(Shared.builder().other(LAST).build()).build())
                    .build())));

        //= specification/searchable-encryption/beacons.md#shared-initialization
        //= type=test
        //# This beacon's [length](#beacon-length) MUST be equal to the `other` beacon's [length](#beacon-length).
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a Shared beacon with a length differing from its target must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] shared beacon chain rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void sharedBeaconChainRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // a -> b -> c: a shared beacon whose target is itself shared is a chain.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("cbeacon").length(10).build(),
                StandardBeacon.builder().name("bbeacon").length(10)
                    .style(BeaconStyle.builder().shared(Shared.builder().other("cbeacon").build()).build())
                    .build(),
                StandardBeacon.builder().name("abeacon").length(10)
                    .style(BeaconStyle.builder().shared(Shared.builder().other("bbeacon").build()).build())
                    .build())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put("abeacon", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("bbeacon", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("cbeacon", CryptoAction.ENCRYPT_AND_SIGN);
        // Dafny Beacon.dfy ChainedShare: share chains are not allowed.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, actions, search),
            "a shared-beacon chain must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] compound beacon with no constructors/parts rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void compoundBeaconWithNoConstructorsRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // A compound with no constructors, no local parts, and no global parts
        // to default from cannot be constructed.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder().name(FIRST).length(10).build()))
            .compoundBeacons(List.of(
                CompoundBeacon.builder().name("bareCompound").split(".").build())));
        // Dafny Beacon.dfy CompoundNoConstructor.
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a compound beacon with no constructors and no local parts must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] empty standard-beacon name rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void emptyBeaconNameRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(StandardBeacon.builder().name("").length(10).build())));
        // Dafny BeaconPartition.dfy TestEmptyBeaconName: an empty beacon name is
        // an invalid configuration rejected at construction (the exact message is
        // a DBE-internal detail, not part of the black-box contract).
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "an empty beacon name must be rejected on " + pair);
    }

    /** Two ENCRYPT_AND_SIGN attributes plus the partition key. */
    private static Map<String, CryptoAction> beaconActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        return actions;
    }

    /** A valid two-part compound beacon ({@code F-<first>.L-<last>}) over global
     *  encrypted parts — the same construct proven valid by
     *  {@link CompoundAndVirtualSearchMetadataTests}. Each new case below is a
     *  single invalid mutation ON TOP of this base, so the rejection is
     *  attributable to the intended defect. */
    private static CompoundBeacon validFirstLastCompound() {
        return CompoundBeacon.builder()
            .name("firstLast").split(".")
            .constructors(List.of(Constructor.builder()
                .parts(List.of(
                    ConstructorPart.builder().name(FIRST).required(true).build(),
                    ConstructorPart.builder().name(LAST).required(true).build()))
                .build()))
            .build();
    }

    @ParameterizedTest(name = "[beacon] shared beacon referencing a compound beacon rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void sharedBeaconReferencingCompoundRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // `shareToCompound` is Shared to the compound beacon `firstLast` — Shared
        // may only reference a standard beacon.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build(),
                StandardBeacon.builder().name("shareToCompound").length(10)
                    .style(BeaconStyle.builder().shared(Shared.builder().other("firstLast").build()).build())
                    .build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(validFirstLastCompound())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("shareToCompound", CryptoAction.ENCRYPT_AND_SIGN);
        // Dafny Beacon.dfy SharedBadReferenceToCompound: "shared to <X> but <X> is a compound beacon."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, actions, search),
            "a standard beacon Shared to a compound beacon must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] global encrypted part referencing an unconfigured beacon rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void globalEncryptedPartReferencingUnconfiguredBeaconRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // The version-level (global) encrypted parts list names `notConfigured`,
        // which is not a configured standard beacon.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build(),
                EncryptedPart.builder().name("notConfigured").prefix("Q-").build()))
            .compoundBeacons(List.of(validFirstLastCompound())));
        // Dafny Beacon.dfy GlobalPartNotExist: "Global Parts List refers to standard beacon <X> which is not configured."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a global encrypted part referencing an unconfigured standard beacon must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] duplicate prefix in the global parts list rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void duplicateGlobalPrefixRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Two global encrypted parts (`last` and `dup`) share the prefix "L-".
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build(),
                StandardBeacon.builder().name("dup").length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build(),
                EncryptedPart.builder().name("dup").prefix("L-").build()))
            .compoundBeacons(List.of(validFirstLastCompound())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("dup", CryptoAction.ENCRYPT_AND_SIGN);
        // Dafny Beacon.dfy DuplicateGlobalPrefix: "Duplicate prefix <X_> in Global Parts List."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, actions, search),
            "a duplicate prefix in the global parts list must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] duplicate name in the global encrypted parts list rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void duplicateGlobalEncryptedPartNameRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // The global encrypted parts list defines `first` twice (distinct prefixes).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build(),
                EncryptedPart.builder().name(FIRST).prefix("G-").build()))
            .compoundBeacons(List.of(validFirstLastCompound())));
        // Dafny Beacon.dfy DuplicateGlobalEncrypted: "Duplicate part name <X> in Global Parts List."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a duplicate name in the global encrypted parts list must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] duplicate name in the global signed parts list rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void duplicateGlobalSignedPartNameRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // The global signed parts list defines `yr` twice (distinct prefixes).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .signedParts(List.of(
                SignedPart.builder().name("yr").prefix("Y-").loc("yr").build(),
                SignedPart.builder().name("yr").prefix("Z-").loc("yr").build()))
            .compoundBeacons(List.of(validFirstLastCompound())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("yr", CryptoAction.SIGN_ONLY);
        // Dafny Beacon.dfy DuplicateGlobalSigned: "Duplicate part name <X> in Global Parts List."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, actions, search),
            "a duplicate name in the global signed parts list must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] compound-local encrypted part colliding with a global part rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void globalVsLocalEncryptedPartCollisionRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // The compound defines a LOCAL encrypted part `first` that is also a global
        // encrypted part.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("firstLast").split(".")
                .encrypted(List.of(EncryptedPart.builder().name(FIRST).prefix("F-").build()))
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));
        // Dafny Beacon.dfy DuplicateGlobalVsLocalEncrypted: "Compound beacon <X> defines encrypted part <Y> which is already defined as a global part."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a compound-local encrypted part colliding with a global part must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] compound-local signed part colliding with a global part rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void globalVsLocalSignedPartCollisionRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // The compound defines a LOCAL signed part `yr` that is also a global signed part.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .signedParts(List.of(
                SignedPart.builder().name("yr").prefix("Y-").loc("yr").build()))
            .compoundBeacons(List.of(CompoundBeacon.builder()
                .name("firstLast").split(".")
                .signed(List.of(SignedPart.builder().name("yr").prefix("Z-").loc("yr").build()))
                .constructors(List.of(Constructor.builder()
                    .parts(List.of(
                        ConstructorPart.builder().name(FIRST).required(true).build(),
                        ConstructorPart.builder().name(LAST).required(true).build()))
                    .build()))
                .build())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("yr", CryptoAction.SIGN_ONLY);
        // Dafny Beacon.dfy DuplicateGlobalVsLocalSigned: "Compound beacon <X> defines signed part <Y> which is already defined as a global part."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, actions, search),
            "a compound-local signed part colliding with a global part must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] two virtual fields on the same locations rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void twoVirtualFieldsOnSameLocationsRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // Two virtual fields (each beaconed) draw from the same set of locations
        // (first, last) — only differing in order.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("vf1").length(10).build(),
                StandardBeacon.builder().name("vf2").length(10).build()))
            .virtualFields(List.of(
                VirtualField.builder().name("vf1").parts(List.of(
                    VirtualPart.builder().loc(FIRST).build(),
                    VirtualPart.builder().loc(LAST).build())).build(),
                VirtualField.builder().name("vf2").parts(List.of(
                    VirtualPart.builder().loc(LAST).build(),
                    VirtualPart.builder().loc(FIRST).build())).build())));
        // Dafny ConfigToInfo.dfy TestTwoVirtOneLoc: "Virtual field <X> is defined on the same locations as <Y>."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "two virtual fields over the same locations must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] a beacon and a virtual field on the same single location rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void beaconAndVirtualFieldOnSameLocationRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // A virtual field `vfSolo` over the single location `first`, and a standard
        // beacon `beaconOnFirst` also on location `first`.
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name("vfSolo").length(10).build(),
                StandardBeacon.builder().name("beaconOnFirst").length(10).loc(FIRST).build()))
            .virtualFields(List.of(
                VirtualField.builder().name("vfSolo").parts(List.of(
                    VirtualPart.builder().loc(FIRST).build())).build())));
        // Dafny ConfigToInfo.dfy TestVirtAndBeaconSameLoc: "Beacon <X> is defined on location <L>, but virtual field <V> is already defined on that single location."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, beaconActions(), search),
            "a beacon and a virtual field on the same single location must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[beacon] fully-signed compound beacon whose name collides with an attribute rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void fullySignedCompoundBeaconNameCollidesWithAttributeRejected(TargetPair pair) {
        FeatureGate.require(Set.of("searchable-encryption"), pair);
        // A FULLY-SIGNED compound beacon (no encrypted parts) named `collide`, which
        // is also an existing item attribute. A fully-signed compound may not share a
        // name with an attribute (the encrypted variant would be allowed).
        SearchConfig search = beaconSearch(BeaconVersion.builder()
            .standardBeacons(List.of(
                StandardBeacon.builder().name(FIRST).length(10).build(),
                StandardBeacon.builder().name(LAST).length(10).build()))
            .encryptedParts(List.of(
                EncryptedPart.builder().name(FIRST).prefix("F-").build(),
                EncryptedPart.builder().name(LAST).prefix("L-").build()))
            .compoundBeacons(List.of(
                validFirstLastCompound(),
                CompoundBeacon.builder()
                    .name("collide").split(".")
                    .signed(List.of(SignedPart.builder().name("yrPart").prefix("Y-").loc("yr").build()))
                    .constructors(List.of(Constructor.builder()
                        .parts(List.of(ConstructorPart.builder().name("yrPart").required(true).build()))
                        .build()))
                    .build())));
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(FIRST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(LAST, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("collide", CryptoAction.SIGN_ONLY);
        actions.put("yr", CryptoAction.SIGN_ONLY);
        // Dafny ConfigToInfo.dfy TestNSwithEB: "<X> not allowed as a CompoundBeacon because a fully signed beacon cannot have the same name as an existing attribute."
        assertThrows(DBESDKTestServerException.class,
            () -> createBeaconClient(pair, actions, search),
            "a fully-signed compound beacon whose name collides with an attribute must be rejected on " + pair);
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
