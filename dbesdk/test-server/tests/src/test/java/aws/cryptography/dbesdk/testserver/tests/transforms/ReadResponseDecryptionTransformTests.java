package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.BatchGetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchGetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.BatchGetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.BatchWriteItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.KeysAndAttributes;
import aws.cryptography.dbesdk.testserver.client.model.PutRequest;
import aws.cryptography.dbesdk.testserver.client.model.QueryInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryOutput;
import aws.cryptography.dbesdk.testserver.client.model.QueryOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanOutput;
import aws.cryptography.dbesdk.testserver.client.model.ScanOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.TransformsTableConfig;
import aws.cryptography.dbesdk.testserver.client.model.WriteRequest;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK read-path (decrypt-after)
 * transforms. The bounded property under test: <em>a read-path output
 * transform decrypts the items a DDB read would have returned back to their
 * original plaintext.</em>
 *
 * <p>Covered read ops: {@code ScanOutputTransform}, {@code QueryOutputTransform},
 * and {@code BatchGetItemOutputTransform} (GetItem is covered by
 * {@link WriteRequestEncryptionTransformTests}). Each test encrypts an item with the
 * item encryptor on one language, presents it to the other language's output
 * transform as the item a Scan / Query / BatchGet would have returned, and
 * asserts the transform recovers the plaintext — the decrypt-after,
 * cross-language dual of the encrypt-before tests.
 *
 * <p>Also covers the write-path decrypt-after regression
 * ({@code BatchWriteItemOutputTransform}): DynamoDB returns items it could not
 * process in {@code UnprocessedItems} still encrypted, and the transform must
 * restore each to its original plaintext so a caller can resubmit it
 * (fix 7c7c8a11).
 *
 * <p>No real DynamoDB is involved: the encrypted item is fed directly into the
 * output transform as the read response, the technique the DBE library's own
 * transform unit tests use.
 */
class ReadResponseDecryptionTransformTests {

    /** A second physical table, bound in the same transforms client as {@link #TABLE}. */
    private static final String TABLE_B = "dbesdk-test-server-table-b";

    /** The sort-key attribute name for the composite-key restore config. */
    private static final String SORT = "sort";

    @ParameterizedTest(name = "[transform] ScanOutputTransform decrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanOutputTransformDecryptsItems(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> encrypted = encryptItem(pair, plaintext);

        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        ScanOutput transformed = decryptClient.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ScanInput.builder().tableName(TABLE).build())
                .sdkOutput(ScanOutput.builder().items(List.of(encrypted)).build())
                .build()).getTransformedOutput();

        assertNotNull(transformed.getItems(), "ScanOutputTransform returned no items on " + pair);
        assertEquals(1, transformed.getItems().size(),
            "ScanOutputTransform must return one item on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
        //= type=test
        //# the corresponding Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md)
        //# where the input [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is this list entry.
        assertItemRoundTrips(plaintext, transformed.getItems().get(0), pair);
    }

    @ParameterizedTest(name = "[transform] QueryOutputTransform decrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryOutputTransformDecryptsItems(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> encrypted = encryptItem(pair, plaintext);

        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        QueryOutput transformed = decryptClient.queryOutputTransform(
            QueryOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(QueryInput.builder().tableName(TABLE).build())
                .sdkOutput(QueryOutput.builder().items(List.of(encrypted)).build())
                .build()).getTransformedOutput();

        assertNotNull(transformed.getItems(), "QueryOutputTransform returned no items on " + pair);
        assertEquals(1, transformed.getItems().size(),
            "QueryOutputTransform must return one item on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
        //= type=test
        //# the corresponding Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md)
        //# where the input [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is this list entry.
        assertItemRoundTrips(plaintext, transformed.getItems().get(0), pair);
    }

    @ParameterizedTest(name = "[transform] BatchGetItemOutputTransform decrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchGetItemOutputTransformDecryptsItems(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> encrypted = encryptItem(pair, plaintext);

        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        BatchGetItemOutput transformed = decryptClient.batchGetItemOutputTransform(
            BatchGetItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(BatchGetItemInput.builder()
                    .requestItems(Map.of(TABLE, KeysAndAttributes.builder()
                        .keys(List.of(Map.of(PK, plaintext.get(PK))))
                        .build()))
                    .build())
                .sdkOutput(BatchGetItemOutput.builder()
                    .responses(Map.of(TABLE, List.of(encrypted)))
                    .build())
                .build()).getTransformedOutput();

        Map<String, List<Map<String, AttributeValue>>> responses = transformed.getResponses();
        assertNotNull(responses, "BatchGetItemOutputTransform returned no responses on " + pair);
        List<Map<String, AttributeValue>> items = responses.get(TABLE);
        assertNotNull(items, "BatchGetItemOutputTransform returned no items for the table on " + pair);
        assertEquals(1, items.size(),
            "BatchGetItemOutputTransform must return one item on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
        //= type=test
        //# that Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md) where the input
        //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is the `Item` field in the original response.
        assertItemRoundTrips(plaintext, items.get(0), pair);
    }

    @ParameterizedTest(name = "[transform] ScanOutputTransform empty result passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanOutputTransformOnEmptyResultPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        ScanOutput transformed = decryptClient.scanOutputTransform(
            ScanOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ScanInput.builder().tableName(TABLE).build())
                .sdkOutput(ScanOutput.builder().items(List.of()).build())
                .build()).getTransformedOutput();

        // An empty scan result decrypts to an empty result — represented as
        // either an absent or an empty item list on the wire, depending on the
        // server runtime; both mean "no items".
        assertTrue(transformed.getItems() == null || transformed.getItems().isEmpty(),
            "empty ScanOutputTransform must yield no items on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchWriteItem UnprocessedItems restored to plaintext {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchWriteItemOutputTransformRestoresUnprocessedItemsToPlaintext(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        // Encrypt the item exactly as a BatchWriteItem PutRequest would send it.
        String encryptClientId = DbeTestHelpers.newTransformsClient(encryptClient, TABLE);
        Map<String, List<WriteRequest>> encryptedRequestItems =
            encryptClient.batchWriteItemInputTransform(
                BatchWriteItemInputTransformInput.builder()
                    .clientId(encryptClientId)
                    .sdkInput(BatchWriteItemInput.builder()
                        .requestItems(Map.of(TABLE, List.of(putRequest(plaintext))))
                        .build())
                    .build()).getTransformedInput().getRequestItems();
        Map<String, AttributeValue> encryptedItem =
            encryptedRequestItems.get(TABLE).get(0).getPutRequest().getItem();

        // Simulate DynamoDB returning that encrypted item as an unprocessed
        // write; the output transform must restore it to plaintext, matched
        // against the original request by primary key.
        String decryptClientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        Map<String, List<WriteRequest>> restored =
            decryptClient.batchWriteItemOutputTransform(
                BatchWriteItemOutputTransformInput.builder()
                    .clientId(decryptClientId)
                    .originalInput(BatchWriteItemInput.builder()
                        .requestItems(Map.of(TABLE, List.of(putRequest(plaintext))))
                        .build())
                    .sdkOutput(BatchWriteItemOutput.builder()
                        .unprocessedItems(Map.of(TABLE, List.of(putRequest(encryptedItem))))
                        .build())
                    .build()).getTransformedOutput().getUnprocessedItems();

        assertNotNull(restored, "UnprocessedItems missing after transform on " + pair);
        Map<String, AttributeValue> recovered =
            restored.get(TABLE).get(0).getPutRequest().getItem();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchwriteitem
        //= type=test
        //# Each item in UnprocessedItems MUST be replaced by its original plaintext value.
        assertItemRoundTrips(plaintext, recovered, pair);
    }

    @ParameterizedTest(name = "[transform] BatchWriteItem UnprocessedItems restored across tables {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchWriteItemOutputRestoresUnprocessedAcrossTables(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        // Two items per table, each with a distinct primary key so the restore
        // must match them back individually.
        Map<String, AttributeValue> a = distinctItem("a1");
        Map<String, AttributeValue> b = distinctItem("a2");
        Map<String, AttributeValue> c = distinctItem("b1");
        Map<String, AttributeValue> d = distinctItem("b2");
        Map<String, List<WriteRequest>> original = Map.of(
            TABLE, List.of(putRequest(a), putRequest(b)),
            TABLE_B, List.of(putRequest(c), putRequest(d)));

        // Encrypt every item exactly as BatchWriteItem PutRequests would send
        // them, through one transforms client bound to both tables.
        String encryptClientId = multiTableClient(encryptClient);
        Map<String, List<WriteRequest>> encrypted =
            encryptClient.batchWriteItemInputTransform(
                BatchWriteItemInputTransformInput.builder()
                    .clientId(encryptClientId)
                    .sdkInput(BatchWriteItemInput.builder().requestItems(original).build())
                    .build()).getTransformedInput().getRequestItems();

        // Simulate DynamoDB returning every encrypted item as unprocessed across
        // both tables; the output transform restores each to its original
        // plaintext, matched to the original request by primary key.
        // Dafny BatchWriteItemTransform.dfy TestBatchWriteItemOutputTransformUnprocessed2:
        // the restore spans multiple tables in a single request map.
        String decryptClientId = multiTableClient(decryptClient);
        Map<String, List<WriteRequest>> restored =
            decryptClient.batchWriteItemOutputTransform(
                BatchWriteItemOutputTransformInput.builder()
                    .clientId(decryptClientId)
                    .originalInput(BatchWriteItemInput.builder().requestItems(original).build())
                    .sdkOutput(BatchWriteItemOutput.builder().unprocessedItems(encrypted).build())
                    .build()).getTransformedOutput().getUnprocessedItems();

        assertNotNull(restored, "UnprocessedItems missing after transform on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchwriteitem
        //= type=test
        //# Each item in UnprocessedItems MUST be replaced by its original plaintext value.
        assertRestores(restored.get(TABLE), List.of(a, b), pair);
        assertRestores(restored.get(TABLE_B), List.of(c, d), pair);
    }

    @ParameterizedTest(name = "[transform] BatchWriteItem partial UnprocessedItems restored by key {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchWriteItemOutputRestoresPartialUnprocessedByKey(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        Map<String, AttributeValue> a = distinctItem("a1");
        Map<String, AttributeValue> b = distinctItem("a2");
        Map<String, AttributeValue> c = distinctItem("b1");
        Map<String, AttributeValue> d = distinctItem("b2");
        Map<String, List<WriteRequest>> original = Map.of(
            TABLE, List.of(putRequest(a), putRequest(b)),
            TABLE_B, List.of(putRequest(c), putRequest(d)));

        String encryptClientId = multiTableClient(encryptClient);
        Map<String, List<WriteRequest>> encrypted =
            encryptClient.batchWriteItemInputTransform(
                BatchWriteItemInputTransformInput.builder()
                    .clientId(encryptClientId)
                    .sdkInput(BatchWriteItemInput.builder().requestItems(original).build())
                    .build()).getTransformedInput().getRequestItems();

        // Only a SUBSET came back unprocessed: the first item of each table
        // (encrypted "a1" and "b1"). The input transform preserves per-table
        // order, so index 0 is the encrypted first item.
        Map<String, List<WriteRequest>> unprocessed = Map.of(
            TABLE, List.of(encrypted.get(TABLE).get(0)),
            TABLE_B, List.of(encrypted.get(TABLE_B).get(0)));

        // The output transform must restore exactly that subset, each matched
        // back to the right original by primary key — not the whole request.
        // Dafny BatchWriteItemTransform.dfy TestBatchWriteItemOutputTransformUnprocessed3:
        // a partial unprocessed list is matched key-by-key against the original.
        String decryptClientId = multiTableClient(decryptClient);
        Map<String, List<WriteRequest>> restored =
            decryptClient.batchWriteItemOutputTransform(
                BatchWriteItemOutputTransformInput.builder()
                    .clientId(decryptClientId)
                    .originalInput(BatchWriteItemInput.builder().requestItems(original).build())
                    .sdkOutput(BatchWriteItemOutput.builder().unprocessedItems(unprocessed).build())
                    .build()).getTransformedOutput().getUnprocessedItems();

        assertNotNull(restored, "UnprocessedItems missing after transform on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchwriteitem
        //= type=test
        //# Each item in UnprocessedItems MUST be replaced by its original plaintext value.
        assertRestores(restored.get(TABLE), List.of(a), pair);
        assertRestores(restored.get(TABLE_B), List.of(c), pair);
    }

    @ParameterizedTest(name = "[transform] BatchWriteItem UnprocessedItems restored by composite key {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchWriteItemOutputRestoresByCompositeKey(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        // Two items sharing one partition key value, distinguished only by their
        // sort key — and carrying distinct secrets. A partition-only match would
        // return the wrong original for at least one of them; only a composite
        // (partition + sort) match restores each to its own plaintext.
        Map<String, AttributeValue> x = compositeItem("p1", "s1");
        Map<String, AttributeValue> y = compositeItem("p1", "s2");
        Map<String, List<WriteRequest>> original =
            Map.of(TABLE, List.of(putRequest(x), putRequest(y)));

        String encryptClientId = compositeKeyClient(encryptClient);
        Map<String, List<WriteRequest>> encrypted =
            encryptClient.batchWriteItemInputTransform(
                BatchWriteItemInputTransformInput.builder()
                    .clientId(encryptClientId)
                    .sdkInput(BatchWriteItemInput.builder().requestItems(original).build())
                    .build()).getTransformedInput().getRequestItems();

        // Dafny BatchWriteItemTransform.dfy TestBatchWriteItemOutputTransformUnprocessed4:
        // items share a partition key and are matched back by the full
        // (partition + sort) key (GetOrigItem compares both key attributes).
        String decryptClientId = compositeKeyClient(decryptClient);
        Map<String, List<WriteRequest>> restored =
            decryptClient.batchWriteItemOutputTransform(
                BatchWriteItemOutputTransformInput.builder()
                    .clientId(decryptClientId)
                    .originalInput(BatchWriteItemInput.builder().requestItems(original).build())
                    .sdkOutput(BatchWriteItemOutput.builder().unprocessedItems(encrypted).build())
                    .build()).getTransformedOutput().getUnprocessedItems();

        assertNotNull(restored, "UnprocessedItems missing after transform on " + pair);
        List<WriteRequest> table = restored.get(TABLE);
        assertNotNull(table, "restored table list missing on " + pair);
        assertEquals(2, table.size(), "both composite-keyed items must be restored on " + pair);
        Map<String, AttributeValue> gotX = findByCompositeKey(table, "p1", "s1");
        Map<String, AttributeValue> gotY = findByCompositeKey(table, "p1", "s2");
        assertNotNull(gotX, "no restored item for composite key (p1,s1) on " + pair);
        assertNotNull(gotY, "no restored item for composite key (p1,s2) on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchwriteitem
        //= type=test
        //# Each item in UnprocessedItems MUST be replaced by its original plaintext value.
        assertItemRoundTrips(x, gotX, pair);
        assertItemRoundTrips(y, gotY, pair);
    }

    @ParameterizedTest(name = "[transform] GetItemOutputTransform on missing item passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void getItemOutputOnMissingItemPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        GetItemOutput transformed = decryptClient.getItemOutputTransform(
            GetItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(GetItemInput.builder()
                    .tableName(TABLE)
                    .key(Map.of(PK, AttributeValue.builder().s("missing").build()))
                    .build())
                .sdkOutput(GetItemOutput.builder().build())
                .build()).getTransformedOutput();
        // A GetItem that matched nothing has no item to decrypt: the transform
        // must skip decryption and pass through (no item, no throw).
        assertTrue(transformed.getItem() == null || transformed.getItem().isEmpty(),
            "GetItemOutputTransform on a missing item must yield no item on " + pair);
    }

    @ParameterizedTest(name = "[transform] QueryOutputTransform empty result passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryOutputOnEmptyResultPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        QueryOutput transformed = decryptClient.queryOutputTransform(
            QueryOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(QueryInput.builder().tableName(TABLE).build())
                .sdkOutput(QueryOutput.builder().items(List.of()).build())
                .build()).getTransformedOutput();
        assertTrue(transformed.getItems() == null || transformed.getItems().isEmpty(),
            "empty QueryOutputTransform must yield no items on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchGetItemOutputTransform empty response passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchGetItemOutputOnEmptyResponsePassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        BatchGetItemOutput transformed = decryptClient.batchGetItemOutputTransform(
            BatchGetItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(BatchGetItemInput.builder()
                    .requestItems(Map.of(TABLE, KeysAndAttributes.builder()
                        .keys(List.of(Map.of(PK, AttributeValue.builder().s("none").build())))
                        .build()))
                    .build())
                .sdkOutput(BatchGetItemOutput.builder().build())
                .build()).getTransformedOutput();
        assertTrue(transformed.getResponses() == null || transformed.getResponses().isEmpty(),
            "empty BatchGetItemOutputTransform must yield no responses on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchWriteItemOutputTransform no unprocessed passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchWriteItemOutputNoUnprocessedPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(decryptClient, TABLE);
        BatchWriteItemOutput transformed = decryptClient.batchWriteItemOutputTransform(
            BatchWriteItemOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(BatchWriteItemInput.builder()
                    .requestItems(Map.of(TABLE, List.of(putRequest(canonicalPlaintext()))))
                    .build())
                .sdkOutput(BatchWriteItemOutput.builder().build())
                .build()).getTransformedOutput();
        assertTrue(
            transformed.getUnprocessedItems() == null || transformed.getUnprocessedItems().isEmpty(),
            "a BatchWriteItem response with no UnprocessedItems must pass through on " + pair);
    }

    // ---------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------

    /** A BatchWriteItem PutRequest carrying {@code item}. */
    private static WriteRequest putRequest(Map<String, AttributeValue> item) {
        return WriteRequest.builder().putRequest(PutRequest.builder().item(item).build()).build();
    }

    /** A transforms client bound to both {@link #TABLE} and {@link #TABLE_B}. */
    private static String multiTableClient(DBESDKTestServerClient client) {
        return client.createTransformsClient(
            CreateTransformsClientInput.builder()
                .config(DbeTestHelpers.transformsConfig(TABLE, null))
                .tableName(TABLE)
                .additionalTables(List.of(TransformsTableConfig.builder()
                    .tableName(TABLE_B)
                    .config(DbeTestHelpers.transformsConfig(TABLE_B, null))
                    .build()))
                .build())
            .getClientId();
    }

    /** A transforms client for {@link #TABLE} with a composite (partition + {@link #SORT}) key. */
    private static String compositeKeyClient(DBESDKTestServerClient client) {
        return client.createTransformsClient(
            CreateTransformsClientInput.builder()
                .config(DbeTestHelpers.transformsConfigWithSortKey(TABLE, SORT))
                .tableName(TABLE)
                .build())
            .getClientId();
    }

    /**
     * The {@link DbeTestHelpers#canonicalPlaintext()} item with its partition
     * key set to {@code pk} and a secret unique to {@code pk}, so a mismatched
     * restore is detectable.
     */
    private static Map<String, AttributeValue> distinctItem(String pk) {
        Map<String, AttributeValue> item = canonicalPlaintext();
        item.put(PK, AttributeValue.builder().s(pk).build());
        item.put(DbeTestHelpers.SECRET, AttributeValue.builder().s("secret-" + pk).build());
        return item;
    }

    /**
     * The {@link DbeTestHelpers#canonicalPlaintext()} item bearing composite key
     * ({@code pk}, {@code sort}) and a secret unique to that composite key, so a
     * partition-only mismatch is detectable.
     */
    private static Map<String, AttributeValue> compositeItem(String pk, String sort) {
        Map<String, AttributeValue> item = canonicalPlaintext();
        item.put(PK, AttributeValue.builder().s(pk).build());
        item.put(SORT, AttributeValue.builder().s(sort).build());
        item.put(DbeTestHelpers.SECRET,
            AttributeValue.builder().s("secret-" + pk + "-" + sort).build());
        return item;
    }

    /**
     * Assert {@code restored} holds exactly the {@code expected} plaintext items,
     * each matched by partition key and round-tripping to its original.
     */
    private static void assertRestores(
            List<WriteRequest> restored,
            List<Map<String, AttributeValue>> expected,
            TargetPair pair) {
        assertNotNull(restored, "restored table list missing on " + pair);
        assertEquals(expected.size(), restored.size(),
            "restored item count must match the unprocessed count on " + pair);
        for (Map<String, AttributeValue> want : expected) {
            Map<String, AttributeValue> got = findByPk(restored, want.get(PK).getS());
            assertNotNull(got,
                "no restored item for PK '" + want.get(PK).getS() + "' on " + pair);
            assertItemRoundTrips(want, got, pair);
        }
    }

    /** The PutRequest item in {@code reqs} whose partition key equals {@code pk}, or null. */
    private static Map<String, AttributeValue> findByPk(List<WriteRequest> reqs, String pk) {
        for (WriteRequest wr : reqs) {
            Map<String, AttributeValue> item = wr.getPutRequest().getItem();
            if (item != null && pk.equals(item.get(PK).getS())) {
                return item;
            }
        }
        return null;
    }

    /** The PutRequest item in {@code reqs} whose composite ({@link #PK}, {@link #SORT}) key matches, or null. */
    private static Map<String, AttributeValue> findByCompositeKey(
            List<WriteRequest> reqs, String pk, String sort) {
        for (WriteRequest wr : reqs) {
            Map<String, AttributeValue> item = wr.getPutRequest().getItem();
            if (item != null
                    && pk.equals(item.get(PK).getS())
                    && sort.equals(item.get(SORT).getS())) {
                return item;
            }
        }
        return null;
    }

    /** Encrypt {@code plaintext} with the item encryptor on the encrypt endpoint. */
    private static Map<String, AttributeValue> encryptItem(
            TargetPair pair, Map<String, AttributeValue> plaintext) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String cid = DbeTestHelpers.newKmsClient(
            encryptClient, TABLE, PK, standardActions(), List.of());
        return DbeTestHelpers.encryptOnce(encryptClient, cid, plaintext);
    }

    private static void assertItemRoundTrips(
            Map<String, AttributeValue> plaintext,
            Map<String, AttributeValue> recovered,
            TargetPair pair) {
        for (Map.Entry<String, AttributeValue> entry : plaintext.entrySet()) {
            AttributeValue actual = recovered.get(entry.getKey());
            assertNotNull(actual,
                "recovered item missing attribute '" + entry.getKey() + "' on " + pair);
            assertEquals(entry.getValue().getS(), actual.getS(),
                "attribute '" + entry.getKey() + "' did not round-trip on " + pair);
        }
    }
}
