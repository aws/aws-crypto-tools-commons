package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.FOOT;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.Delete;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Put;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.UpdateItemInput;
import aws.cryptography.dbesdk.testserver.client.model.UpdateItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.UpdateItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.DeleteItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DeleteItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.DeleteItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.PutRequest;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItem;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItemsInput;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItemsInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItemsOutput;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItemsOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.WriteRequest;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK write-path (encrypt-before)
 * transforms. The bounded property under test: <em>a write-path input
 * transform encrypts the item(s) it would write, and the resulting encrypted
 * item is decrypted back to the original plaintext by another language's
 * transform.</em>
 *
 * <p>Covered write ops: {@code PutItemInputTransform},
 * {@code BatchWriteItemInputTransform} (per PutRequest), and
 * {@code TransactWriteItemsInputTransform} (per Put action). Each item is
 * encrypted on one language's transforms client and recovered on another's
 * {@code GetItemOutputTransform}, so a cross-language pair proves the write
 * transforms produce a wire-compatible encrypted item — the transform-surface
 * dual of {@link ItemEncryptionInteropRoundTripTests}.
 *
 * <p>No real DynamoDB is involved: the encrypted item a write transform would
 * have written is fed straight into {@code GetItemOutputTransform} as the item
 * a {@code GetItem} would have returned — the technique the DBE library's own
 * transform unit tests use.
 *
 * <p>Later sub-rounds add the decrypt-after output transforms (Scan / Query /
 * BatchGet / TransactGet), PartiQL rejection, passthrough guards, and the
 * beacon rewrite.
 */
class WriteRequestEncryptionTransformTests {

    @ParameterizedTest(name = "[transform] PutItemInputTransform encrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putItemInputTransformEncryptsItem(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> encrypted =
            putItemInputTransform(encryptClient, canonicalPlaintext());
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //= type=test
        //# The PutItem request's `Item` field MUST be replaced
        //# with a value that is equivalent to
        //# the output of the [add encrypted beacons](ddb-support.md#addencryptedbeacons) operation
        //# calculated above.
        assertEncryptedItem(encrypted, pair);
    }

    @ParameterizedTest(name = "[transform] PutItem→Get transform round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putThenGetOutputTransformRoundTripsPlaintext(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> encrypted = putItemInputTransform(encryptClient, plaintext);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
        //= type=test
        //# The [Item Encryptor](./ddb-item-encryptor.md) MUST perform
        //# [Decrypt Item](./decrypt-item.md) where the input
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is the `Item` field in the original response
        assertRecovers(plaintext, encrypted, pair);
    }

    @ParameterizedTest(name = "[transform] BatchWriteItemInputTransform encrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchWriteItemInputTransformEncryptsAndRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        String clientId = DbeTestHelpers.newTransformsClient(encryptClient, TABLE);
        BatchWriteItemInput input = BatchWriteItemInput.builder()
            .requestItems(Map.of(TABLE, List.of(
                WriteRequest.builder()
                    .putRequest(PutRequest.builder().item(plaintext).build())
                    .build())))
            .build();
        Map<String, List<WriteRequest>> transformed = encryptClient.batchWriteItemInputTransform(
            BatchWriteItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(input)
                .build()).getTransformedInput().getRequestItems();

        Map<String, AttributeValue> encrypted =
            transformed.get(TABLE).get(0).getPutRequest().getItem();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
        //= type=test
        //# The PutRequest request's `Item` field MUST be replaced
        //# with a value that is equivalent to
        //# the result [Encrypted DynamoDB Item](./encrypt-item.md#encrypted-dynamodb-item)
        //# calculated above.
        assertEncryptedItem(encrypted, pair);
        assertRecovers(plaintext, encrypted, pair);
    }

    @ParameterizedTest(name = "[transform] TransactWriteItemsInputTransform encrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void transactWriteItemsInputTransformEncryptsAndRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        String clientId = DbeTestHelpers.newTransformsClient(encryptClient, TABLE);
        TransactWriteItemsInput input = TransactWriteItemsInput.builder()
            .transactItems(List.of(TransactWriteItem.builder()
                .put(Put.builder().tableName(TABLE).item(plaintext).build())
                .build()))
            .build();
        Map<String, AttributeValue> encrypted = encryptClient.transactWriteItemsInputTransform(
            TransactWriteItemsInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(input)
                .build()).getTransformedInput().getTransactItems().get(0).getPut().getItem();

        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
        //= type=test
        //# - The PutItem request's `Item` field MUST be replaced
        //#   with a value that is equivalent to
        //#   the result [Encrypted DynamoDB Item](./encrypt-item.md#encrypted-dynamodb-item)
        //#   calculated above.
        assertEncryptedItem(encrypted, pair);
        assertRecovers(plaintext, encrypted, pair);
    }

    @ParameterizedTest(name = "[transform] PutItemInputTransform on unconfigured table passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putItemInputOnUnconfiguredTablePassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(encryptClient, TABLE);
        // The client owns TABLE; a PutItem to a different, unconfigured table
        // must NOT be encrypted — the transform passes it through unchanged.
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        PutItemInput transformed = encryptClient.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder()
                    .tableName("other-unconfigured-table")
                    .item(plaintext)
                    .build())
                .build()).getTransformedInput();
        Map<String, AttributeValue> item = transformed.getItem();
        assertTrue(!item.containsKey(HEAD) && !item.containsKey(FOOT),
            "an unconfigured-table PutItem must not gain DBE header/footer on " + pair);
        assertEquals(plaintext.get(SECRET).getS(), item.get(SECRET).getS(),
            "an unconfigured-table PutItem must keep its plaintext attributes on " + pair);
    }

    @ParameterizedTest(name = "[transform] PutItemOutputTransform on unconfigured table passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putItemOutputOnUnconfiguredTablePassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        // The client owns TABLE; a PutItem response for a different, unconfigured
        // table must pass through unchanged — the modify-after transform does not
        // touch attributes it never encrypted.
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        PutItemOutput transformed = client.putItemOutputTransform(
            PutItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(PutItemInput.builder()
                    .tableName("other-unconfigured-table")
                    .item(plaintext)
                    .build())
                .sdkOutput(PutItemOutput.builder().attributes(plaintext).build())
                .build()).getTransformedOutput();
        Map<String, AttributeValue> attrs = transformed.getAttributes();
        assertNotNull(attrs, "PutItemOutputTransform must return the attributes on " + pair);
        assertTrue(!attrs.containsKey(HEAD) && !attrs.containsKey(FOOT),
            "an unconfigured-table PutItem output must not gain DBE header/footer on " + pair);
        assertEquals(plaintext.get(SECRET).getS(), attrs.get(SECRET).getS(),
            "an unconfigured-table PutItem output must keep its plaintext attributes on " + pair);
    }

    @ParameterizedTest(name = "[transform] UpdateItemOutputTransform on unconfigured table passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void updateItemOutputOnUnconfiguredTablePassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> key =
            Map.of(PK, AttributeValue.builder().s("item-1").build());
        UpdateItemOutput transformed = client.updateItemOutputTransform(
            UpdateItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(UpdateItemInput.builder()
                    .tableName("other-unconfigured-table")
                    .key(key)
                    .build())
                .sdkOutput(UpdateItemOutput.builder().attributes(plaintext).build())
                .build()).getTransformedOutput();
        Map<String, AttributeValue> attrs = transformed.getAttributes();
        assertNotNull(attrs, "UpdateItemOutputTransform must return the attributes on " + pair);
        assertTrue(!attrs.containsKey(HEAD) && !attrs.containsKey(FOOT),
            "an unconfigured-table UpdateItem output must not gain DBE header/footer on " + pair);
        assertEquals(plaintext.get(SECRET).getS(), attrs.get(SECRET).getS(),
            "an unconfigured-table UpdateItem output must keep its plaintext attributes on " + pair);
    }

    @ParameterizedTest(name = "[transform] DeleteItemOutputTransform on unconfigured table passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void deleteItemOutputOnUnconfiguredTablePassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> key =
            Map.of(PK, AttributeValue.builder().s("item-1").build());
        DeleteItemOutput transformed = client.deleteItemOutputTransform(
            DeleteItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(DeleteItemInput.builder()
                    .tableName("other-unconfigured-table")
                    .key(key)
                    .build())
                .sdkOutput(DeleteItemOutput.builder().attributes(plaintext).build())
                .build()).getTransformedOutput();
        Map<String, AttributeValue> attrs = transformed.getAttributes();
        assertNotNull(attrs, "DeleteItemOutputTransform must return the attributes on " + pair);
        assertTrue(!attrs.containsKey(HEAD) && !attrs.containsKey(FOOT),
            "an unconfigured-table DeleteItem output must not gain DBE header/footer on " + pair);
        assertEquals(plaintext.get(SECRET).getS(), attrs.get(SECRET).getS(),
            "an unconfigured-table DeleteItem output must keep its plaintext attributes on " + pair);
    }

    @ParameterizedTest(name = "[transform] TransactWriteItemsOutputTransform passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void transactWriteItemsOutputPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        // TransactWriteItems returns no item content, so the modify-after
        // transform is a passthrough that yields a well-formed empty output.
        TransactWriteItemsOutput transformed = client.transactWriteItemsOutputTransform(
            TransactWriteItemsOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(TransactWriteItemsInput.builder()
                    .transactItems(List.of(TransactWriteItem.builder()
                        .put(Put.builder()
                            .tableName("other-unconfigured-table")
                            .item(canonicalPlaintext())
                            .build())
                        .build()))
                    .build())
                .sdkOutput(TransactWriteItemsOutput.builder().build())
                .build()).getTransformedOutput();
        assertNotNull(transformed,
            "TransactWriteItemsOutputTransform must return an output on " + pair);
    }

    @ParameterizedTest(name = "[transform] TransactWriteItems Delete member passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void transactWriteItemsDeletePassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        // A Delete action has no item to encrypt; with no beacon config the
        // input transform returns it unchanged (Dafny TestTransactWriteItemsInputPassthrough).
        TransactWriteItemsInput sdkInput = TransactWriteItemsInput.builder()
            .transactItems(List.of(TransactWriteItem.builder()
                .delete(Delete.builder()
                    .tableName(TABLE)
                    .key(Map.of(PK, AttributeValue.builder().s("item-1").build()))
                    .build())
                .build()))
            .build();
        TransactWriteItemsInput transformed = client.transactWriteItemsInputTransform(
            TransactWriteItemsInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(sdkInput)
                .build()).getTransformedInput();
        assertEquals(sdkInput, transformed,
            "a Delete transact item must pass through unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] TransactWriteItems item with no action rejected {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void transactWriteItemsEmptyItemRejected(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        // Dafny TestTransactWriteItemsInputEmpty: an item that sets no Put/Delete/
        // Update/ConditionCheck must be rejected.
        assertThrows(DBESDKTestServerException.class, () -> client.transactWriteItemsInputTransform(
            TransactWriteItemsInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(TransactWriteItemsInput.builder()
                    .transactItems(List.of(TransactWriteItem.builder().build()))
                    .build())
                .build()),
            "a transact item with no supported operation must be rejected on " + pair);
    }

    /**
     * PutItemInputTransform enforces the DynamoDB AttributeName byte-length
     * limit (Dafny {@code PutItemTransform.dfy}:
     * {@code TestPutItemAttributeNameTooLongBytes}): a signed attribute whose
     * name is 65536 bytes is rejected by the write-path transform. All three
     * targets reject it (rust-v1 rejects the schema key at
     * {@code CreateTransformsClient} against the model length constraint,
     * java-v3/net-v4 at the transform), so the assertion is on the common
     * supertype. The name is single-byte-char so byte count equals char count.
     */
    @ParameterizedTest(name = "PutItemInputTransform enforces the 65535-byte attribute-name limit {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putItemInputTransformRejectsAttributeNameOverByteLimit(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String overLimitName = "a".repeat(65536);
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(overLimitName, CryptoAction.ENCRYPT_AND_SIGN);
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PK, AttributeValue.builder().s("put-name-key").build());
        item.put(overLimitName, AttributeValue.builder().s("v").build());
        //= specification/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
        //= type=test
        //= reason=a 65536-byte attribute name is not a valid DynamoDB AttributeName, so the write-path transform rejects it
        //# MUST NOT have any `Key` strings that are invalid DynamoDB AttributeNames, that is, with more than 65535 characters.
        assertThrows(DBESDKTestServerException.class, () -> {
            String clientId = DbeTestHelpers.newTransformsClientWithActions(client, TABLE, actions);
            client.putItemInputTransform(PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(item).build())
                .build());
        }, "a 65536-byte attribute name must be rejected by PutItemInputTransform on " + pair);
    }

    // ---------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------
    /**
     * Create a transforms client on {@code client} and run PutItemInputTransform
     * on {@code plaintext}, returning the encrypted item.
     */
    private static Map<String, AttributeValue> putItemInputTransform(
            DBESDKTestServerClient client, Map<String, AttributeValue> plaintext) {
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        PutItemInput transformed = client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder().tableName(TABLE).item(plaintext).build())
                .build()).getTransformedInput();
        assertNotNull(transformed, "PutItemInputTransform returned no transformed input");
        Map<String, AttributeValue> encrypted = transformed.getItem();
        assertNotNull(encrypted, "PutItemInputTransform returned no item");
        return encrypted;
    }

    /** Assert an encrypted item carries the DBE envelope and hides the secret. */
    private static void assertEncryptedItem(
            Map<String, AttributeValue> encrypted, TargetPair pair) {
        assertTrue(encrypted.containsKey(HEAD),
            "encrypted item must carry the DBE header attribute on " + pair);
        assertTrue(encrypted.containsKey(FOOT),
            "encrypted item must carry the DBE footer attribute on " + pair);
        assertNotNull(encrypted.get(SECRET).getB(),
            "ENCRYPT_AND_SIGN 'secret' must become a binary value on " + pair);
        assertNull(encrypted.get(SECRET).getS(),
            "ENCRYPT_AND_SIGN 'secret' must not retain its plaintext string on " + pair);
        assertEquals("item-1", encrypted.get(PK).getS(),
            "signed partition key 'PK' must be preserved verbatim on " + pair);
    }

    /**
     * Decrypt {@code encrypted} on the pair's decrypt endpoint via
     * GetItemOutputTransform and assert every attribute of {@code plaintext} is
     * recovered.
     */
    private static void assertRecovers(
            Map<String, AttributeValue> plaintext,
            Map<String, AttributeValue> encrypted,
            TargetPair pair) {
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String decryptClientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        GetItemOutput transformed = decryptClient.getItemOutputTransform(
            GetItemOutputTransformInput.builder()
                .clientId(decryptClientId)
                .originalInput(GetItemInput.builder()
                    .tableName(TABLE)
                    .key(Map.of(PK, plaintext.get(PK)))
                    .build())
                .sdkOutput(GetItemOutput.builder().item(encrypted).build())
                .build()).getTransformedOutput();

        Map<String, AttributeValue> recovered = transformed.getItem();
        assertNotNull(recovered, "GetItemOutputTransform returned no item on " + pair);
        for (Map.Entry<String, AttributeValue> entry : plaintext.entrySet()) {
            AttributeValue actual = recovered.get(entry.getKey());
            assertNotNull(actual,
                "recovered item missing attribute '" + entry.getKey() + "' on " + pair);
            assertEquals(entry.getValue().getS(), actual.getS(),
                "attribute '" + entry.getKey() + "' did not round-trip on " + pair);
        }
    }
}
