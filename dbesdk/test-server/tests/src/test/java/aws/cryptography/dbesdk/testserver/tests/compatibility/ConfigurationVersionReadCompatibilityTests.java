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
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.v1StandardActions;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
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
 * Configuration-Version READ COMPATIBILITY — a writer on runtime A produces an
 * item under one Configuration Version; a reader on runtime B decrypts it under a
 * (possibly different) Configuration Version. The decrypt path reconstructs the
 * DynamoDB base context from the item's header version byte, so every
 * writer/reader combination MUST recover the plaintext.
 *
 * <p><b>Topology: ordered pairs.</b> A produces, B consumes → run across the pair
 * matrix (via {@link DbeTestHelpers#pairs()}). The producer-side header/legend
 * facts live in {@link ConfigurationVersionWireEncodingTests} (target-local).
 *
 * <p>All four combinations are kept distinct — collapsing them into one generic
 * round-trip would lose the {@code 0x01}/{@code 0x02} writer/reader distinction:
 * <ul>
 *   <li>V1 writer → V1 reader</li>
 *   <li>V1 writer → V2 reader (backward compatibility during a v1→v2 migration)</li>
 *   <li>V2 writer → V2 reader</li>
 *   <li>V2 writer → V1 reader (forward compatibility for a lagging reader)</li>
 * </ul>
 * plus a v1 all-{@code SIGN_ONLY} integrity-only round-trip.
 */
class ConfigurationVersionReadCompatibilityTests {

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /**
     * Encrypt {@code plaintext} on the pair's encrypt endpoint under {@code writerActions},
     * decrypt on the decrypt endpoint under {@code readerActions}, and assert every
     * plaintext value is recovered.
     */
    private static void assertReadCompat(TargetPair pair, String label,
            Map<String, CryptoAction> writerActions, Map<String, CryptoAction> readerActions) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, writerActions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, readerActions, List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId)
            .encryptedItem(item)
            .build());
        //= specification/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
        //= type=test
        //= reason=the reader reconstructs the base context from the item's header version byte, so the plaintext is recovered regardless of the reader's own configuration version
        //# If the Version Number is 1, the base context MUST be the [version 1](./encrypt-item.md#dynamodb-item-base-context-version-1) context.
        assertPlaintextPreserved(label, decrypted, pair);
    }

    @ParameterizedTest(name = "V1 writer -> V1 reader round-trips {0}")
    @MethodSource("testPairs")
    void v1WriterV1ReaderRoundTrips(TargetPair pair) {
        assertReadCompat(pair, "v1->v1", v1StandardActions(), v1StandardActions());
    }

    @ParameterizedTest(name = "V1 writer -> V2 reader round-trips (backward compat) {0}")
    @MethodSource("testPairs")
    void v1WriterV2ReaderRoundTrips(TargetPair pair) {
        assertReadCompat(pair, "v1->v2", v1StandardActions(), standardActions());
    }

    @ParameterizedTest(name = "V2 writer -> V2 reader round-trips {0}")
    @MethodSource("testPairs")
    void v2WriterV2ReaderRoundTrips(TargetPair pair) {
        assertReadCompat(pair, "v2->v2", standardActions(), standardActions());
    }

    @ParameterizedTest(name = "V2 writer -> V1 reader round-trips (forward compat) {0}")
    @MethodSource("testPairs")
    void v2WriterV1ReaderRoundTrips(TargetPair pair) {
        assertReadCompat(pair, "v2->v1", standardActions(), v1StandardActions());
    }

    /**
     * A v1 all-{@code SIGN_ONLY} schema (no attribute encrypted) round-trips: the
     * library still emits and verifies a valid header + recipient tag when the
     * encryption stage is a no-op, and every signed attribute is returned
     * unchanged — the integrity-only mode a v1 config permits.
     */
    @ParameterizedTest(name = "v1 all-SIGN_ONLY schema round-trips {0}")
    @MethodSource("testPairs")
    void v1AllSignOnlyRoundTrips(TargetPair pair) {
        Map<String, CryptoAction> allSignOnly = new LinkedHashMap<>();
        allSignOnly.put(PK, CryptoAction.SIGN_ONLY);
        allSignOnly.put(SECRET, CryptoAction.SIGN_ONLY);
        allSignOnly.put(PUBLIC, CryptoAction.SIGN_ONLY);
        //= specification/structured-encryption/structures.md#do-not-encrypt
        //= type=test
        //= reason=every attribute is SIGN_ONLY (DO_NOT_ENCRYPT); round-trip returns each value unchanged
        //# DO_NOT_ENCRYPT signifies that the [Terminal Data](#terminal-data)
        //# MUST have an equal [Terminal Value](#terminal-value) and
        //# [Terminal Type Id](#terminal-type-id) as the the Terminal Data
        //# in the same location in the resulting encrypted [Structured Data](#structured-data).
        assertReadCompat(pair, "v1 all-SIGN_ONLY", allSignOnly, allSignOnly);
    }
}
