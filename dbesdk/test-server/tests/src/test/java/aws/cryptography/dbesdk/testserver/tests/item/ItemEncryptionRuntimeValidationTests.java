package aws.cryptography.dbesdk.testserver.tests.item;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClientWithSortKey;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Per-item, encrypt-time validation failures of the item encryptor (Dafny
 * {@code DynamoDBItemEncryptorTest.dfy}: {@code TestUnexpectedField},
 * {@code TestMissingSortKey}, {@code TestMissingContext}). Distinct from
 * {@code ItemEncryptionConfigurationValidationTests}, which rejects invalid
 * <em>configurations</em> at {@code CreateClient}: here the config is valid and
 * a runtime <em>item</em> violates it, so the failure is at {@code EncryptItem}.
 *
 * <p>Target-local: each is an encrypt-side rejection. The rejection error class
 * varies by adapter, so the assertion is on the common supertype.
 */
class ItemEncryptionRuntimeValidationTests {

    static Stream<LanguageServerTarget> targets() {
        return DbeTestHelpers.targets().stream();
    }

    @ParameterizedTest(name = "EncryptItem rejects an unconfigured attribute {0}")
    @MethodSource("targets")
    void encryptItemRejectsUnconfiguredAttribute(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, standardActions(), List.of());
        // The item adds an attribute with no Crypto Action in the schema.
        Map<String, AttributeValue> item = canonicalPlaintext();
        item.put("unknown", AttributeValue.builder().s("surprise").build());
        assertThrows(DBESDKTestServerException.class, () -> encryptOnce(client, clientId, item),
            "an item attribute absent from the schema must be rejected at encrypt on " + target);
    }

    @ParameterizedTest(name = "EncryptItem rejects an item missing its sort key {0}")
    @MethodSource("targets")
    void encryptItemRejectsItemMissingSortKey(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        Map<String, CryptoAction> actions = standardActions();
        actions.put("sort", CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        String clientId = newKmsClientWithSortKey(client, TABLE, PK, "sort", actions, List.of());
        // canonicalPlaintext has PK/secret/public but no declared sort key.
        assertThrows(DBESDKTestServerException.class,
            () -> encryptOnce(client, clientId, canonicalPlaintext()),
            "an item missing its declared sort key must be rejected at encrypt on " + target);
    }

    @ParameterizedTest(name = "EncryptItem rejects a missing SIGN_AND_INCLUDE attribute {0}")
    @MethodSource("targets")
    void encryptItemRejectsMissingSignAndIncludeAttribute(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, standardActions(), List.of());
        // 'public' is SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT; omit it from the item.
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("item-1").build());
        item.put(SECRET, AttributeValue.builder().s("hunter2").build());
        assertThrows(DBESDKTestServerException.class, () -> encryptOnce(client, clientId, item),
            "a v2 item omitting a SIGN_AND_INCLUDE attribute (" + PUBLIC
                + ") must be rejected at encrypt on " + target);
    }

    /**
     * The item serializer rejects an item nested past {@code MAX_STRUCTURE_DEPTH}
     * (32) with a {@code DBESDKClientError} naming the limit (Dafny
     * {@code DynamoToStruct.dfy}: {@code TestTooDeep}). An item nested to the
     * limit is accepted (see
     * {@code ItemEncryptionBoundaryBehaviorTests#maxDepthNestedItemRoundTrips});
     * one level over is rejected here.
     *
     * <p>The java-v3 target cannot exercise this boundary: smithy-java 1.4.0
     * overflows a fixed-size validator path array while validating the
     * recursive request shape (a framework {@code InternalFailureException})
     * well below the product's depth limit, so on java-v3 the product depth
     * guard is never reached. That is a declared, visible known bug
     * ({@code java-deep-nesting-request-validation-overflow}); net-v4 and
     * rust-v1 assert the product behavior, and if a smithy-java upgrade lets
     * java-v3 reach the guard the gate fails loudly so the ledger entry is
     * retired.
     */
    @ParameterizedTest(name = "EncryptItem rejects an item nested past the depth limit {0}")
    @MethodSource("targets")
    void encryptItemRejectsOverMaxDepth(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put("value", CryptoAction.ENCRYPT_AND_SIGN);
        String clientId = newKmsClient(client, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("too-deep").build());
        // 32 nested maps exceeds MAX_STRUCTURE_DEPTH; 31 accepts (see the paired
        // round-trip test); net-v4/rust-v1 reject 32 with "exceeds limit of 32".
        item.put("value", DbeTestHelpers.deeplyNestedMap(32));
        KnownBugGate.gateDeclared(
            "java-deep-nesting-request-validation-overflow",
            target,
            () -> {
                DBESDKClientError error = assertThrows(DBESDKClientError.class,
                    () -> encryptOnce(client, clientId, item),
                    "an item nested past the depth limit must be rejected at encrypt on " + target);
                assertTrue(
                    error.getMessage() != null && error.getMessage().contains("exceeds limit of 32"),
                    "the depth rejection must name the structure-depth limit; got: "
                        + error.getMessage() + " on " + target);
            });
    }

    /**
     * The item serializer enforces the DynamoDB AttributeName byte-length limit
     * (Dafny {@code DynamoToStruct.dfy}: {@code TestAttributeNameTooLongBytes}):
     * a top-level attribute name of exactly 65535 bytes encrypts, and one of
     * 65536 bytes is rejected. All three targets reject the over-limit name;
     * the layer differs (rust-v1 rejects the schema key at {@code CreateClient}
     * against the model's length constraint, java-v3/net-v4 reject at
     * {@code EncryptItem}), so the assertion is on the common supertype.
     */
    @ParameterizedTest(name = "EncryptItem enforces the 65535-byte attribute-name limit {0}")
    @MethodSource("targets")
    void encryptItemEnforcesAttributeNameByteLimit(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // At the limit: a 65535-byte (single-byte-char) attribute name encrypts.
        encryptWithNamedAttribute(client, "a".repeat(65535));
        //= specification/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
        //= type=test
        //= reason=an attribute name over 65535 bytes is not a valid DynamoDB AttributeName, so encrypt rejects it
        //# MUST NOT have any `Key` strings that are invalid DynamoDB AttributeNames, that is, with more than 65535 characters.
        assertThrows(DBESDKTestServerException.class,
            () -> encryptWithNamedAttribute(client, "a".repeat(65536)),
            "a 65536-byte attribute name must be rejected on " + target);
    }

    /**
     * Build a client whose schema signs+encrypts an attribute named
     * {@code attributeName}, then encrypt an item carrying it. Both
     * {@code CreateClient} and {@code EncryptItem} run so a rejection at either
     * layer surfaces (rust-v1 rejects the schema key at build; java-v3/net-v4
     * at encrypt).
     */
    private static void encryptWithNamedAttribute(
            DBESDKTestServerClient client, String attributeName) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(attributeName, CryptoAction.ENCRYPT_AND_SIGN);
        String clientId = newKmsClient(client, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("name-limit-key").build());
        item.put(attributeName, AttributeValue.builder().s("v").build());
        encryptOnce(client, clientId, item);
    }
}
