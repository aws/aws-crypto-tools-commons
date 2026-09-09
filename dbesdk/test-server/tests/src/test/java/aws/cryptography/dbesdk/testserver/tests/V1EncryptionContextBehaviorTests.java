package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptLegendBytes;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.v1StandardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Configuration Version 1 encryption-context behavior — how items encrypted under
 * a v1 schema (no {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}) manifest on the
 * wire and interoperate with v2 clients.
 *
 * <p>The Configuration Version is chosen by the presence or absence of
 * {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} in the schema
 * ({@code specification/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version}).
 * This file exercises the v1 side.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #v1ConfigProducesVersionByte01} — header byte 0 encodes v1</li>
 *   <li>{@link #v1EncryptLegendEncodesActionsAsExpected} — legend bytes encode SIGN_ONLY as 's', ENCRYPT_AND_SIGN as 'e'</li>
 *   <li>{@link #v1RoundTripPreservesPlaintext} — positive round-trip fidelity</li>
 *   <li>{@link #v1EncryptedItemDecryptsUnderV2Client} — backward compat: migrating from v1 to v2 doesn't strand prior rows</li>
 *   <li>{@link #v1AllSignOnlyRoundTripPreservesPlaintext} — v1 schema where every attribute is SIGN_ONLY (no ENCRYPT_AND_SIGN); integrity-only mode</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 5 assertions × pairs²}.
 */
class V1EncryptionContextBehaviorTests {

    /** Header byte 0 for v1 items — per header.md#format-version. */
    private static final byte VERSION_V1 = 0x01;

    /** Encrypt Legend byte for {@code ENCRYPT_AND_SIGN}. */
    private static final byte LEGEND_ENCRYPT_AND_SIGN = 0x65; // 'e'

    /** Encrypt Legend byte for {@code SIGN_ONLY}. */
    private static final byte LEGEND_SIGN_ONLY = 0x73; // 's'

    private record V1Context(TargetPair pair, Map<String, AttributeValue> encryptedItem) {}

    private static final Map<TargetPair, V1Context> CONTEXTS = new ConcurrentHashMap<>();

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static V1Context contextFor(TargetPair pair) {
        return CONTEXTS.computeIfAbsent(pair, p -> {
            DBESDKTestServerClient encryptClient =
                DbeTestServerClients.forEndpoint(p.encryptEndpoint());
            String encryptClientId =
                newKmsClient(encryptClient, TABLE, PK, v1StandardActions(), List.of());
            Map<String, AttributeValue> item =
                encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
            return new V1Context(p, item);
        });
    }

    /** A schema with no SIGN_AND_INCLUDE anywhere is v1 → header version byte is 0x01. */
    @ParameterizedTest(name = "v1 config → version byte 0x01 {0}")
    @MethodSource("testPairs")
    void v1ConfigProducesVersionByte01(TargetPair pair) {
        byte[] header = bytesOf(contextFor(pair).encryptedItem().get(HEAD));
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version
        //= type=test
        //# If any of the [Attribute Actions](#attribute-actions) are configured as
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
        //# then the configuration version MUST be 2; otherwise,
        //# the configuration version MUST be 1.
        assertEquals(VERSION_V1, header[0],
            "a schema without SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT must produce a header whose "
                + "version byte is 0x01 (" + pair + ")");
    }

    /**
     * v1 legend byte encoding: {@code SIGN_ONLY} attributes encode as 's' (0x73);
     * {@code ENCRYPT_AND_SIGN} as 'e' (0x65). Attributes appear in lexicographic
     * canonical-path order → for our schema (PK, public, secret) the legend is
     * {@code "sse"}. This test also implicitly asserts the legend length matches
     * the number of authenticated attributes (3).
     */
    @ParameterizedTest(name = "v1 encrypt legend encodes actions as s/s/e {0}")
    @MethodSource("testPairs")
    void v1EncryptLegendEncodesActionsAsExpected(TargetPair pair) {
        byte[] legend = encryptLegendBytes(contextFor(pair).encryptedItem());
        //= specification/structured-encryption/header.md#encrypt-legend
        //= type=test
        //# The Encrypt Legend Bytes MUST have 1 byte for every authenticated field ...
        //# and MUST use the same order as those fields, encoding each as:
        //# - 0x65 'e' ENCRYPT_AND_SIGN
        //# - 0x73 's' SIGN_ONLY
        //# - 0x63 'c' SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT
        assertEquals(3, legend.length,
            "v1 encrypt legend must have one byte per authenticated attribute (schema has 3): "
                + pair);
        assertEquals(LEGEND_SIGN_ONLY, legend[0],
            "v1 legend[0] must be 0x73 ('s') for PK=SIGN_ONLY (" + pair + ")");
        assertEquals(LEGEND_SIGN_ONLY, legend[1],
            "v1 legend[1] must be 0x73 ('s') for public=SIGN_ONLY (" + pair + ")");
        assertEquals(LEGEND_ENCRYPT_AND_SIGN, legend[2],
            "v1 legend[2] must be 0x65 ('e') for secret=ENCRYPT_AND_SIGN (" + pair + ")");
    }

    /** v1 encrypt → v1 decrypt preserves every plaintext attribute value. */
    @ParameterizedTest(name = "v1 round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void v1RoundTripPreservesPlaintext(TargetPair pair) {
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, v1StandardActions(), List.of());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId)
            .encryptedItem(contextFor(pair).encryptedItem())
            .build());
        //= specification/structured-encryption/structures.md#encrypt
        //= type=test
        //= reason=round-trip recovers the ENCRYPT_AND_SIGN 'secret' value, proving it was decrypted
        //# During [Decrypt Structure](decrypt-structure.md#decrypt-structure),
        //# ENCRYPT signifies that the [Terminal Value](#terminal-value) in the [Terminal Data](#terminal-data)
        //# MUST be attempted to be decrypted.
        assertPlaintextPreserved("v1", decrypted, pair);
    }

    /**
     * v1-encrypted items decrypt under v2-configured clients — backward compatibility.
     * Clients migrating from v1 to v2 do not lose access to previously encrypted rows.
     */
    @ParameterizedTest(name = "v1 encrypt → v2 client decrypt succeeds {0}")
    @MethodSource("testPairs")
    void v1EncryptedItemDecryptsUnderV2Client(TargetPair pair) {
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, standardActions(), List.of());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId)
            .encryptedItem(contextFor(pair).encryptedItem())
            .build());
        //= specification/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
        //= type=test
        //= reason=v1 item decrypts under a v2-config client, proving base context follows the header version byte
        //# If the Version Number is 1, the base context MUST be the [version 1](./encrypt-item.md#dynamodb-item-base-context-version-1) context.
        assertPlaintextPreserved("v1→v2", decrypted, pair);
    }

    /**
     * All-{@code SIGN_ONLY} v1 schema variant: no attribute is encrypted, every
     * signed attribute is preserved as plaintext through the item. Round-trip
     * proves the DBE library still emits/verifies a valid header + recipient
     * tag when the encryption stage is a no-op — a v1 config permits this
     * shape ({@code SIGN_ONLY} is legal for every attribute), and users may
     * pick it when they need integrity but not confidentiality.
     */
    @ParameterizedTest(name = "v1 all-SIGN_ONLY schema round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void v1AllSignOnlyRoundTripPreservesPlaintext(TargetPair pair) {
        Map<String, CryptoAction> allSignOnly = new LinkedHashMap<>();
        allSignOnly.put(PK, CryptoAction.SIGN_ONLY);
        allSignOnly.put(SECRET, CryptoAction.SIGN_ONLY);
        allSignOnly.put(PUBLIC, CryptoAction.SIGN_ONLY);

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, allSignOnly, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, allSignOnly, List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId)
            .encryptedItem(item)
            .build());
        //= specification/structured-encryption/structures.md#do_not_encrypt
        //= type=test
        //= reason=every attribute is SIGN_ONLY (DO_NOT_ENCRYPT); round-trip returns each value unchanged
        //# DO_NOT_ENCRYPT signifies that the [Terminal Data](#terminal-data)
        //# MUST have an equal [Terminal Value](#terminal-value) and
        //# [Terminal Type Id](#terminal-type-id) as the the Terminal Data
        //# in the same location in the resulting encrypted [Structured Data](#structured-data).
        assertPlaintextPreserved("v1 all-SIGN_ONLY", decrypted, pair);
    }
}
