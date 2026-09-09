package aws.cryptography.dbesdk.testserver.tests;

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
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Put;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.PutRequest;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItem;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItemsInput;
import aws.cryptography.dbesdk.testserver.client.model.TransactWriteItemsInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.WriteRequest;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK write-path (encrypt-before)
 * transforms (§0.3.3). The bounded property under test: <em>a write-path input
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
 * dual of {@link DbeRoundTripTests}.
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
class EncryptBeforeTransformTests {

    @ParameterizedTest(name = "[transform] PutItemInputTransform encrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putItemInputTransformEncryptsItem(TargetPair pair) {
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
