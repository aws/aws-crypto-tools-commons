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
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
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
 * Configuration Version 2 encryption-context behavior — how items encrypted under
 * a v2 schema (any attribute uses {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT})
 * manifest on the wire, interoperate with v1 clients, and how CreateClient
 * validates schema shape.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #v2ConfigProducesVersionByte02} — header byte 0 encodes v2</li>
 *   <li>{@link #v2EncryptLegendEncodesActionsAsExpected} — legend bytes encode SIGN_AND_INCLUDE as 'c', ENCRYPT_AND_SIGN as 'e'</li>
 *   <li>{@link #v2RoundTripPreservesPlaintext} — positive round-trip fidelity; in a cross-language run
 *       (via {@code make orchestrate}) this also implicitly proves that every runtime computes matching
 *       {@code aws-crypto-attr.*} entries — those entries are in the signed canonical hash but not the header
 *       EC on the wire, so mismatched implementations would surface here as a signature-verification failure.</li>
 *   <li>{@link #v2EncryptedItemDecryptsUnderV1Client} — forward compat</li>
 *   <li>{@link #v2RejectsReservedPrefixAttributeName} — CreateClient rejects attribute names using the reserved
 *       {@code aws_dbe_} prefix; the same rule applies under v1, so testing under one Configuration Version
 *       is sufficient.</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 5 assertions × pairs²}.
 */
class V2EncryptionContextBehaviorTests {

    /** Header byte 0 for v2 items — per header.md#format-version. */
    private static final byte VERSION_V2 = 0x02;

    /** Encrypt Legend byte for {@code ENCRYPT_AND_SIGN}. */
    private static final byte LEGEND_ENCRYPT_AND_SIGN = 0x65; // 'e'

    /** Encrypt Legend byte for {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}. */
    private static final byte LEGEND_SIGN_AND_INCLUDE = 0x63; // 'c'

    /** Reserved attribute-name prefix — cannot appear in any user-configured schema. */
    private static final String RESERVED_PREFIX_NAME = "aws_dbe_reserved";

    private record V2Context(TargetPair pair, Map<String, AttributeValue> encryptedItem) {}

    private static final Map<TargetPair, V2Context> CONTEXTS = new ConcurrentHashMap<>();

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static V2Context contextFor(TargetPair pair) {
        return CONTEXTS.computeIfAbsent(pair, p -> {
            DBESDKTestServerClient encryptClient =
                DbeTestServerClients.forEndpoint(p.encryptEndpoint());
            String encryptClientId =
                newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
            Map<String, AttributeValue> item =
                encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
            return new V2Context(p, item);
        });
    }

    /** A v2 schema produces a header with version byte 0x02. */
    @ParameterizedTest(name = "v2 config → version byte 0x02 {0}")
    @MethodSource("testPairs")
    void v2ConfigProducesVersionByte02(TargetPair pair) {
        byte[] header = bytesOf(contextFor(pair).encryptedItem().get(HEAD));
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version
        //= type=test
        //# If any of the [Attribute Actions](#attribute-actions) are configured as
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
        //# then the configuration version MUST be 2; otherwise,
        //# the configuration version MUST be 1.
        assertEquals(VERSION_V2, header[0],
            "a v2 schema must produce a header whose version byte is 0x02 (" + pair + ")");
    }

    /**
     * v2 legend byte encoding: {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} → 'c'
     * (0x63); {@code ENCRYPT_AND_SIGN} → 'e' (0x65). Canonical-path order → for our
     * schema the legend is {@code "cce"} (PK, public are context-participating; secret
     * is encrypted-and-signed).
     */
    @ParameterizedTest(name = "v2 encrypt legend encodes actions as c/c/e {0}")
    @MethodSource("testPairs")
    void v2EncryptLegendEncodesActionsAsExpected(TargetPair pair) {
        byte[] legend = encryptLegendBytes(contextFor(pair).encryptedItem());
        //= specification/structured-encryption/header.md#encrypt-legend
        //= type=test
        //# The Encrypt Legend Bytes MUST have 1 byte for every authenticated field ...
        //# and MUST use the same order as those fields, encoding each as:
        //# - 0x65 'e' ENCRYPT_AND_SIGN
        //# - 0x73 's' SIGN_ONLY
        //# - 0x63 'c' SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT
        assertEquals(3, legend.length,
            "v2 encrypt legend must have one byte per authenticated attribute (schema has 3): "
                + pair);
        assertEquals(LEGEND_SIGN_AND_INCLUDE, legend[0],
            "v2 legend[0] must be 0x63 ('c') for PK=SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT ("
                + pair + ")");
        assertEquals(LEGEND_SIGN_AND_INCLUDE, legend[1],
            "v2 legend[1] must be 0x63 ('c') for public=SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT ("
                + pair + ")");
        assertEquals(LEGEND_ENCRYPT_AND_SIGN, legend[2],
            "v2 legend[2] must be 0x65 ('e') for secret=ENCRYPT_AND_SIGN (" + pair + ")");
    }

    /** v2 encrypt → v2 decrypt preserves every plaintext attribute value. */
    @ParameterizedTest(name = "v2 round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void v2RoundTripPreservesPlaintext(TargetPair pair) {
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, standardActions(), List.of());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId)
            .encryptedItem(contextFor(pair).encryptedItem())
            .build());
        assertPlaintextPreserved("v2", decrypted, pair);
    }

    /**
     * v2-encrypted items decrypt under v1-configured clients — forward compatibility
     * so a v1 reader can still consume rows produced by a newer v2 writer.
     */
    @ParameterizedTest(name = "v2 encrypt → v1 client decrypt succeeds {0}")
    @MethodSource("testPairs")
    void v2EncryptedItemDecryptsUnderV1Client(TargetPair pair) {
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, v1StandardActions(), List.of());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId)
            .encryptedItem(contextFor(pair).encryptedItem())
            .build());
        assertPlaintextPreserved("v2→v1", decrypted, pair);
    }

    /**
     * Attribute names beginning with the {@code aws_dbe_} reserved prefix MUST be
     * rejected at CreateClient. The library uses that prefix for its own on-wire
     * attributes ({@code aws_dbe_head}, {@code aws_dbe_foot}), and letting a user
     * schema shadow them would silently corrupt encrypted items.
     */
    @ParameterizedTest(name = "CreateClient rejects reserved-prefix attribute name {0}")
    @MethodSource("testPairs")
    void v2RejectsReservedPrefixAttributeName(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, CryptoAction> reservedActions = new LinkedHashMap<>();
        reservedActions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        reservedActions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        reservedActions.put(PUBLIC, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        reservedActions.put(RESERVED_PREFIX_NAME, CryptoAction.SIGN_ONLY);
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md
        //= type=test
        //# The name of every attribute in the item MUST NOT begin with the
        //# reserved prefix "aws_dbe_".
        assertThrows(DBESDKTestServerException.class,
            () -> newKmsClient(client, TABLE, PK, reservedActions, List.of()),
            "CreateClient must reject a schema whose attribute name starts with the reserved "
                + "'aws_dbe_' prefix (" + pair + ")");
    }
}
