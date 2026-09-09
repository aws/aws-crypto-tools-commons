package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * CreateClient-time schema validation rules the DBE library MUST enforce
 * before the client is ever used to encrypt or decrypt. Every test here calls
 * only {@code CreateClient}; there is no encrypt/decrypt.
 *
 * <p><b>Rules covered:</b>
 * <ul>
 *   <li>Partition key action — MUST be {@code SIGN_ONLY} under a v1 schema and
 *       {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} under a v2 schema, and MUST
 *       NOT be {@code DO_NOTHING} under either.</li>
 *   <li>{@code DO_NOTHING} / allowed-unsigned bidirectional pairing — every
 *       {@code DO_NOTHING} attribute MUST be listed in {@code allowedUnsignedAttributes},
 *       and every attribute in {@code allowedUnsignedAttributes} MUST have action
 *       {@code DO_NOTHING}.</li>
 *   <li>Partition key MUST be declared in the action map.</li>
 * </ul>
 *
 * <p><b>Test count</b> = {@code 7 assertions × pairs}. Only the encrypt-side
 * endpoint is exercised — {@code CreateClient} runs entirely on one server, so
 * the decrypt-side isn't needed and the pair matrix runs one leg per pair.
 */
class ClientConfigValidationTests {

    private static final String OPTIONAL_ATTR = "optional";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    // =========================================================================
    // Partition-key action rules.
    // =========================================================================

    /**
     * A v1 schema whose partition-key action is not {@code SIGN_ONLY} MUST be
     * rejected at CreateClient — v1 requires the partition key to be
     * {@code SIGN_ONLY}.
     */
    @ParameterizedTest(name = "v1 rejects partition key ENCRYPT_AND_SIGN {0}")
    @MethodSource("testPairs")
    void v1RejectsPartitionKeyEncryptAndSign(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.ENCRYPT_AND_SIGN); // illegal under v1
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#key-action
        //= type=test
        //# otherwise, the key action MUST be [SIGN_ONLY](../structured-encryption/structures.md#signonly).
        assertRejectsCreateClient(pair, actions, List.of(),
            "v1 schema with PK=ENCRYPT_AND_SIGN must be rejected — v1 requires PK=SIGN_ONLY");
    }

    /**
     * A v2 schema whose partition-key action is not
     * {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} MUST be rejected at
     * CreateClient — v2 requires the partition key to be
     * {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}. Here the v2 config is
     * triggered by another attribute using that action.
     */
    @ParameterizedTest(name = "v2 rejects partition key SIGN_ONLY {0}")
    @MethodSource("testPairs")
    void v2RejectsPartitionKeySignOnly(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY); // illegal under v2
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT); // triggers v2
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#key-action
        //= type=test
        //# if the [configuration version](#configuration-version) is 2, then
        //# the key action MUST be [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign);
        assertRejectsCreateClient(pair, actions, List.of(),
            "v2 schema with PK=SIGN_ONLY must be rejected — v2 requires "
                + "PK=SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT");
    }

    /**
     * The partition key MUST NOT be {@code DO_NOTHING} under either version —
     * an unsigned, unencrypted primary key would strip integrity from the row's
     * identity.
     */
    @ParameterizedTest(name = "rejects partition key DO_NOTHING {0}")
    @MethodSource("testPairs")
    void rejectsPartitionKeyDoNothing(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.DO_NOTHING); // illegal for primary key
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#key-action
        //= type=test
        //# if the [configuration version](#configuration-version) is 2, then
        //# the key action MUST be [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign);
        //# otherwise, the key action MUST be [SIGN_ONLY](../structured-encryption/structures.md#signonly).
        assertRejectsCreateClient(pair, actions, List.of(PK),
            "schema with PK=DO_NOTHING must be rejected — primary key can't be unsigned");
    }

    /**
     * The partition key attribute MUST appear in the action map. A schema that
     * declares {@code partitionKeyName=PK} but has no entry for {@code PK} in
     * its action map is invalid.
     */
    @ParameterizedTest(name = "rejects schema missing the partition key attribute {0}")
    @MethodSource("testPairs")
    void rejectsSchemaMissingPartitionKey(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        // PK deliberately omitted
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#attribute-actions
        //= type=test
        //# The [Key Action](#key-action)
        //# MUST be configured to the partition attribute and, if present, sort attribute.
        assertRejectsCreateClient(pair, actions, List.of(),
            "schema missing the declared partition key attribute must be rejected");
    }

    // =========================================================================
    // DO_NOTHING / allowedUnsignedAttributes bidirectional pairing.
    // =========================================================================

    /**
     * An attribute with action {@code DO_NOTHING} MUST also be listed in
     * {@code allowedUnsignedAttributes}. Without that pairing, the schema
     * declares an attribute the library will neither sign nor allow to bypass —
     * an ambiguity the library refuses at config time.
     */
    @ParameterizedTest(name = "rejects DO_NOTHING attribute not in allowedUnsigned {0}")
    @MethodSource("testPairs")
    void rejectsDoNothingAttributeNotInAllowedUnsigned(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        actions.put(OPTIONAL_ATTR, CryptoAction.DO_NOTHING); // DO_NOTHING but not in allowedUnsigned
        assertRejectsCreateClient(pair, actions, List.of(),
            "DO_NOTHING attribute not listed in allowedUnsignedAttributes must be rejected");
    }

    /**
     * An attribute listed in {@code allowedUnsignedAttributes} MUST have action
     * {@code DO_NOTHING}. The pairing goes both ways: listing an attribute as
     * unsigned while giving it a cryptographic action contradicts itself.
     */
    @ParameterizedTest(name = "rejects allowedUnsigned attribute with non-DO_NOTHING action {0}")
    @MethodSource("testPairs")
    void rejectsAllowedUnsignedAttributeWithNonDoNothingAction(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        actions.put(OPTIONAL_ATTR, CryptoAction.SIGN_ONLY); // in allowedUnsigned but not DO_NOTHING
        assertRejectsCreateClient(pair, actions, List.of(OPTIONAL_ATTR),
            "attribute in allowedUnsignedAttributes with non-DO_NOTHING action must be rejected");
    }

    /**
     * The positive counterpart to the two rejection tests above: a
     * {@code DO_NOTHING} attribute that IS in {@code allowedUnsignedAttributes}
     * is a valid config and CreateClient succeeds.
     */
    @ParameterizedTest(name = "accepts DO_NOTHING attribute in allowedUnsigned {0}")
    @MethodSource("testPairs")
    void acceptsDoNothingAttributeInAllowedUnsigned(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        actions.put(OPTIONAL_ATTR, CryptoAction.DO_NOTHING);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = newKmsClient(client, TABLE, PK, actions, List.of(OPTIONAL_ATTR));
        assertNotNull(clientId,
            "CreateClient must succeed when every DO_NOTHING attribute is listed in "
                + "allowedUnsignedAttributes (" + pair + ")");
    }

    // =========================================================================
    // Helpers.
    // =========================================================================

    /**
     * Assert that {@code CreateClient} rejects the given schema. Accepts any
     * subclass of {@link DBESDKTestServerException} — CreateClient failures
     * arrive as {@code GenericServerError} while runtime crypto failures
     * arrive as {@code DBESDKClientError}, both sharing this common parent.
     */
    private static void assertRejectsCreateClient(
            TargetPair pair,
            Map<String, CryptoAction> actions,
            List<String> allowedUnsigned,
            String message) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        assertThrows(DBESDKTestServerException.class,
            () -> newKmsClient(client, TABLE, PK, actions, allowedUnsigned),
            message + " (" + pair + ")");
    }
}
