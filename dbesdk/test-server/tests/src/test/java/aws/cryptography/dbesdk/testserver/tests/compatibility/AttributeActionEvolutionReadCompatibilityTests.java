package aws.cryptography.dbesdk.testserver.tests.compatibility;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Attribute-action / schema EVOLUTION read compatibility — a writer on runtime A
 * encrypts an item under one set of {@code attributeActionsOnEncrypt}; a reader on
 * runtime B decrypts it under a DIFFERENT set (a changed action for an existing
 * attribute, or an attribute added to / removed from the reader's schema). This is
 * the cross-language counterpart of the DB-ESDK Dafny TestVectors
 * ({@code TestVectors/dafny/DDBEncryption/src/WriteManifest.dfy}), whose per-test
 * write/decrypt configs each scenario mirrors; the Dafny vectors validate this
 * per-language, this suite validates it across the producer/consumer matrix.
 *
 * <p>Sibling {@link ConfigurationVersionReadCompatibilityTests} varies the
 * configuration VERSION (header {@code 0x01}/{@code 0x02}); this one holds the
 * version fixed and varies the attribute actions between write and read.
 *
 * <p>Topology: ordered pairs — A produces, B consumes — via
 * {@link DbeTestHelpers#pairs()}.
 */
class AttributeActionEvolutionReadCompatibilityTests {

    // A fourth attribute, absent from canonicalPlaintext(), used by the
    // add/remove scenarios: only the writer's or reader's schema declares it, so
    // the item never actually carries it (mirrors the vectors' BasicRecord, which
    // omits the "NewThing" attribute the Expanded* configs declare).
    private static final String EXTRA = "extra";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /** Basic schema: partition key signed, both value attributes encrypted. */
    private static Map<String, CryptoAction> basic() {
        Map<String, CryptoAction> a = new LinkedHashMap<>();
        a.put(PK, CryptoAction.SIGN_ONLY);
        a.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        a.put(PUBLIC, CryptoAction.ENCRYPT_AND_SIGN);
        return a;
    }

    /** All value attributes SIGN_ONLY (integrity only, nothing encrypted). */
    private static Map<String, CryptoAction> signOnly() {
        Map<String, CryptoAction> a = new LinkedHashMap<>();
        a.put(PK, CryptoAction.SIGN_ONLY);
        a.put(SECRET, CryptoAction.SIGN_ONLY);
        a.put(PUBLIC, CryptoAction.SIGN_ONLY);
        return a;
    }

    /** {@link #basic()} plus the EXTRA attribute at the given action. */
    private static Map<String, CryptoAction> basicPlusExtra(CryptoAction extraAction) {
        Map<String, CryptoAction> a = basic();
        a.put(EXTRA, extraAction);
        return a;
    }

    /**
     * Encrypt on the pair's encrypt endpoint under {@code writerActions}, decrypt
     * on the decrypt endpoint under {@code readerActions}, and assert every
     * plaintext value is recovered.
     */
    private static void assertEvolvedReadRoundTrips(
            TargetPair pair, String label,
            Map<String, CryptoAction> writerActions, List<String> writerUnsigned,
            Map<String, CryptoAction> readerActions, List<String> readerUnsigned) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptId = newKmsClient(encryptClient, TABLE, PK, writerActions, writerUnsigned);
        String decryptId = newKmsClient(decryptClient, TABLE, PK, readerActions, readerUnsigned);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptId)
            .encryptedItem(item)
            .build());
        assertPlaintextPreserved(label, decrypted, pair);
    }

    /**
     * As above, but the reader is expected to REJECT the item: the reader's
     * actions contradict how the attributes were actually protected, so
     * authentication fails.
     */
    private static void assertEvolvedReadRejected(
            TargetPair pair, String label,
            Map<String, CryptoAction> writerActions, List<String> writerUnsigned,
            Map<String, CryptoAction> readerActions, List<String> readerUnsigned) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptId = newKmsClient(encryptClient, TABLE, PK, writerActions, writerUnsigned);
        String decryptId = newKmsClient(decryptClient, TABLE, PK, readerActions, readerUnsigned);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptId, canonicalPlaintext());
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptId).encryptedItem(item).build()),
            label + " reader must reject an item whose actual actions contradict its config on " + pair);
    }

    // ---- Change an existing attribute's action between write and read --------

    @ParameterizedTest(name = "change ENCRYPT_AND_SIGN -> SIGN_ONLY still reads {0}")
    @MethodSource("testPairs")
    void changeEncryptAndSignToSignOnly(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "E&S->SIGN_ONLY",
            basic(), List.of(), signOnly(), List.of());
    }

    @ParameterizedTest(name = "change SIGN_ONLY -> ENCRYPT_AND_SIGN still reads {0}")
    @MethodSource("testPairs")
    void changeSignOnlyToEncryptAndSign(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "SIGN_ONLY->E&S",
            signOnly(), List.of(), basic(), List.of());
    }

    @ParameterizedTest(name = "change ENCRYPT_AND_SIGN -> DO_NOTHING is rejected {0}")
    @MethodSource("testPairs")
    void changeEncryptAndSignToDoNothingRejected(TargetPair pair) {
        Map<String, CryptoAction> nothing = new LinkedHashMap<>();
        nothing.put(PK, CryptoAction.SIGN_ONLY);
        nothing.put(SECRET, CryptoAction.DO_NOTHING);
        nothing.put(PUBLIC, CryptoAction.DO_NOTHING);
        assertEvolvedReadRejected(pair, "E&S->DO_NOTHING",
            basic(), List.of(), nothing, List.of(SECRET, PUBLIC));
    }

    // ---- Add an attribute the item does not carry (reader's schema wider) ----

    @ParameterizedTest(name = "reader adds a new ENCRYPT_AND_SIGN attribute {0}")
    @MethodSource("testPairs")
    void addNewEncryptAndSignAttribute(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "add E&S attr",
            basic(), List.of(), basicPlusExtra(CryptoAction.ENCRYPT_AND_SIGN), List.of());
    }

    @ParameterizedTest(name = "reader adds a new SIGN_ONLY attribute {0}")
    @MethodSource("testPairs")
    void addNewSignOnlyAttribute(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "add SIGN_ONLY attr",
            basic(), List.of(), basicPlusExtra(CryptoAction.SIGN_ONLY), List.of());
    }

    @ParameterizedTest(name = "reader adds a new DO_NOTHING attribute {0}")
    @MethodSource("testPairs")
    void addNewDoNothingAttribute(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "add DO_NOTHING attr",
            basic(), List.of(),
            basicPlusExtra(CryptoAction.DO_NOTHING), List.of(EXTRA));
    }

    // ---- Remove an attribute (writer's schema wider than the item/reader) ----

    @ParameterizedTest(name = "writer had an extra ENCRYPT_AND_SIGN attribute, reader does not {0}")
    @MethodSource("testPairs")
    void removeEncryptAndSignAttribute(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "remove E&S attr",
            basicPlusExtra(CryptoAction.ENCRYPT_AND_SIGN), List.of(), basic(), List.of());
    }

    @ParameterizedTest(name = "writer had an extra SIGN_ONLY attribute, reader does not {0}")
    @MethodSource("testPairs")
    void removeSignOnlyAttribute(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "remove SIGN_ONLY attr",
            basicPlusExtra(CryptoAction.SIGN_ONLY), List.of(), basic(), List.of());
    }

    @ParameterizedTest(name = "writer had an extra DO_NOTHING attribute, reader does not {0}")
    @MethodSource("testPairs")
    void removeDoNothingAttribute(TargetPair pair) {
        assertEvolvedReadRoundTrips(pair, "remove DO_NOTHING attr",
            basicPlusExtra(CryptoAction.DO_NOTHING), List.of(EXTRA), basic(), List.of());
    }
}
