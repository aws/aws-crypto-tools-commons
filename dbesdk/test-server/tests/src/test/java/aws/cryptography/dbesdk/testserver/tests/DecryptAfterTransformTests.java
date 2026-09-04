package aws.cryptography.dbesdk.testserver.tests;

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
import aws.cryptography.dbesdk.testserver.client.model.KeysAndAttributes;
import aws.cryptography.dbesdk.testserver.client.model.QueryInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryOutput;
import aws.cryptography.dbesdk.testserver.client.model.QueryOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanOutput;
import aws.cryptography.dbesdk.testserver.client.model.ScanOutputTransformInput;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK read-path (decrypt-after)
 * transforms (§0.3.3). The bounded property under test: <em>a read-path output
 * transform decrypts the items a DDB read would have returned back to their
 * original plaintext.</em>
 *
 * <p>Covered read ops: {@code ScanOutputTransform}, {@code QueryOutputTransform},
 * and {@code BatchGetItemOutputTransform} (GetItem is covered by
 * {@link EncryptBeforeTransformTests}). Each test encrypts an item with the
 * item encryptor on one language, presents it to the other language's output
 * transform as the item a Scan / Query / BatchGet would have returned, and
 * asserts the transform recovers the plaintext — the decrypt-after,
 * cross-language dual of the encrypt-before tests.
 *
 * <p>No real DynamoDB is involved: the encrypted item is fed directly into the
 * output transform as the read response, the technique the DBE library's own
 * transform unit tests use.
 */
class DecryptAfterTransformTests {

    @ParameterizedTest(name = "[transform] ScanOutputTransform decrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanOutputTransformDecryptsItems(TargetPair pair) {
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
        assertItemRoundTrips(plaintext, transformed.getItems().get(0), pair);
    }

    @ParameterizedTest(name = "[transform] QueryOutputTransform decrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryOutputTransformDecryptsItems(TargetPair pair) {
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
        assertItemRoundTrips(plaintext, transformed.getItems().get(0), pair);
    }

    @ParameterizedTest(name = "[transform] BatchGetItemOutputTransform decrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchGetItemOutputTransformDecryptsItems(TargetPair pair) {
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
        assertItemRoundTrips(plaintext, items.get(0), pair);
    }

    @ParameterizedTest(name = "[transform] ScanOutputTransform empty result passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanOutputTransformOnEmptyResultPassesThrough(TargetPair pair) {
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

    // ---------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------

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
