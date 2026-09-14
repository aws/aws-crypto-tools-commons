package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DeleteItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DeleteItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.UpdateItemInput;
import aws.cryptography.dbesdk.testserver.client.model.UpdateItemInputTransformInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK validate-before UpdateItem /
 * DeleteItem input transforms. These transforms exercise the DBE
 * library's internal {@code TestUpdateExpression} / {@code TestConditionExpression}
 * helpers, which have no direct RPC surface — the only way to reach them is
 * through the Update/Delete input transforms.
 *
 * <p>The two bounded properties under test:
 * <ul>
 *   <li><em>An UpdateExpression that references a signed attribute is rejected.</em>
 *       Updating a signed attribute out-of-band would invalidate the item
 *       signature, so the transform fails ({@code TestUpdateExpression}: "Update
 *       Expressions forbidden on signed attributes"). An update over only
 *       unsigned (unconfigured / DO_NOTHING) attributes passes through.</li>
 *   <li><em>A ConditionExpression that references an encrypted attribute is
 *       rejected.</em> An encrypted attribute is stored as ciphertext, so a
 *       server-side condition on its value can never hold; the transform fails
 *       ({@code TestConditionExpression}: "Condition Expressions forbidden on
 *       encrypted attributes"). A condition over a signed-but-not-encrypted
 *       attribute passes through.</li>
 * </ul>
 *
 * <p>Grounded in the DBE library's own transform tests
 * ({@code UpdateItemTransform.dfy}: signed/encrypted update expressions fail, a
 * plain-attribute update passes) and interceptor tests
 * ({@code TestUpdateItemOnEncryptedTableBad},
 * {@code TestDeleteItemWithConditionExpression}).
 *
 * <p>Under the schema's {@link DbeTestHelpers#standardActions() standard actions}:
 * {@code secret} is {@code ENCRYPT_AND_SIGN} (encrypted, hence signed);
 * {@code PK} and {@code public} are {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}
 * (signed, not encrypted). Attribute names are referenced through
 * ExpressionAttributeNames placeholders so a DDB reserved word (e.g. {@code public})
 * cannot skew the result.
 *
 * <p>The passthrough cases are the guards that keep the rejection cases honest:
 * a transform that rejected <em>every</em> request would pass the rejection
 * assertions for the wrong reason, so a non-triggering expression must be
 * accepted and returned unchanged.
 *
 * <p>Each transform runs on the pair's encrypt endpoint (validation is local to
 * one server and needs no round-trip), so across the pair matrix every language
 * server is exercised as the target.
 */
class PartialWriteExpressionPolicyTests {

    /** The primary key of the item the Update/Delete would target. */
    private static Map<String, AttributeValue> pkKey() {
        return Map.of(PK, AttributeValue.builder().s("item-1").build());
    }

    @ParameterizedTest(name = "[transform] UpdateItem rejects update expression over signed attribute {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void updateItemRejectsUpdateExpressionOverSignedAttribute(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        //= specification/dynamodb-encryption-client/ddb-support.md#testupdateexpression
        //= type=test
        //# TestUpdateExpression MUST fail if any operand in the update expression is a signed attribute name.
        assertThrows(DBESDKClientError.class, () -> client.updateItemInputTransform(
            UpdateItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(UpdateItemInput.builder()
                    .tableName(TABLE)
                    .key(pkKey())
                    .updateExpression("SET #p = :v")
                    .expressionAttributeNames(Map.of("#p", PUBLIC))
                    .expressionAttributeValues(
                        Map.of(":v", AttributeValue.builder().s("changed").build()))
                    .build())
                .build()),
            "an UpdateExpression touching the signed attribute '" + PUBLIC
                + "' must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[transform] UpdateItem passes through update expression over unsigned attribute {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void updateItemPassesThroughUpdateExpressionOverUnsignedAttribute(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        UpdateItemInput transformed = client.updateItemInputTransform(
            UpdateItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(UpdateItemInput.builder()
                    .tableName(TABLE)
                    .key(pkKey())
                    .updateExpression("SET #n = :v")
                    .expressionAttributeNames(Map.of("#n", "plain"))
                    .expressionAttributeValues(
                        Map.of(":v", AttributeValue.builder().s("changed").build()))
                    .build())
                .build()).getTransformedInput();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-updateitem
        //= type=test
        //# If all of the above validation succeeds, the UpdateItem request MUST be unchanged.
        assertEquals("SET #n = :v", transformed.getUpdateExpression(),
            "an UpdateExpression over an unconfigured (unsigned) attribute must pass through"
                + " unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] DeleteItem rejects condition expression over encrypted attribute {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void deleteItemRejectsConditionExpressionOverEncryptedAttribute(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        //= specification/dynamodb-encryption-client/ddb-support.md#testconditionexpression
        //= type=test
        //# TestConditionExpression MUST fail if any operand in the condition expression is an encrypted attribute name.
        assertThrows(DBESDKClientError.class, () -> client.deleteItemInputTransform(
            DeleteItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(DeleteItemInput.builder()
                    .tableName(TABLE)
                    .key(pkKey())
                    .conditionExpression("#s = :v")
                    .expressionAttributeNames(Map.of("#s", SECRET))
                    .expressionAttributeValues(
                        Map.of(":v", AttributeValue.builder().s("hunter2").build()))
                    .build())
                .build()),
            "a ConditionExpression over the encrypted attribute '" + SECRET
                + "' must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[transform] DeleteItem passes through condition expression over signed-not-encrypted attribute {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void deleteItemPassesThroughConditionExpressionOverSignedAttribute(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        DeleteItemInput transformed = client.deleteItemInputTransform(
            DeleteItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(DeleteItemInput.builder()
                    .tableName(TABLE)
                    .key(pkKey())
                    .conditionExpression("#p = :v")
                    .expressionAttributeNames(Map.of("#p", PUBLIC))
                    .expressionAttributeValues(
                        Map.of(":v", AttributeValue.builder().s("hello world").build()))
                    .build())
                .build()).getTransformedInput();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-deleteitem
        //= type=test
        //# If all of the above validation succeeds, the DeleteItem request MUST be unchanged.
        assertEquals("#p = :v", transformed.getConditionExpression(),
            "a ConditionExpression over the signed-but-not-encrypted attribute '" + PUBLIC
                + "' must pass through unchanged on " + pair);
    }
}
