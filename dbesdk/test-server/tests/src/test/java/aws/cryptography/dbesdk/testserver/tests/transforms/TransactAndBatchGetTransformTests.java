package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.BatchGetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchGetItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Get;
import aws.cryptography.dbesdk.testserver.client.model.ItemResponse;
import aws.cryptography.dbesdk.testserver.client.model.KeysAndAttributes;
import aws.cryptography.dbesdk.testserver.client.model.TransactGetItem;
import aws.cryptography.dbesdk.testserver.client.model.TransactGetItemsInput;
import aws.cryptography.dbesdk.testserver.client.model.TransactGetItemsInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.TransactGetItemsOutput;
import aws.cryptography.dbesdk.testserver.client.model.TransactGetItemsOutputTransformInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the read-path BatchGetItem / TransactGetItems
 * transforms. The bounded property: <em>with no beacon config, a read input
 * transform returns its input unchanged, and the TransactGetItems output
 * transform leaves an unconfigured table's returned items untouched.</em>
 */
class TransactAndBatchGetTransformTests {

    private static Map<String, AttributeValue> key() {
        return Map.of(PK, AttributeValue.builder().s("item-1").build());
    }

    @ParameterizedTest(name = "[transform] BatchGetItemInputTransform passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchGetItemInputPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        BatchGetItemInput sdkInput = BatchGetItemInput.builder()
            .requestItems(Map.of(TABLE,
                KeysAndAttributes.builder().keys(List.of(key())).build()))
            .build();
        BatchGetItemInput transformed = client.batchGetItemInputTransform(
            BatchGetItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(sdkInput)
                .build()).getTransformedInput();
        assertEquals(sdkInput, transformed,
            "BatchGetItemInputTransform without a beacon config must return the input unchanged on "
                + pair);
    }

    @ParameterizedTest(name = "[transform] TransactGetItemsInputTransform passes through {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void transactGetItemsInputPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        TransactGetItemsInput sdkInput = TransactGetItemsInput.builder()
            .transactItems(List.of(TransactGetItem.builder()
                .get(Get.builder().tableName(TABLE).key(key()).build())
                .build()))
            .build();
        TransactGetItemsInput transformed = client.transactGetItemsInputTransform(
            TransactGetItemsInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(sdkInput)
                .build()).getTransformedInput();
        assertEquals(sdkInput, transformed,
            "TransactGetItemsInputTransform without a beacon config must return the input unchanged on "
                + pair);
    }

    @ParameterizedTest(name = "[transform] TransactGetItemsOutputTransform passes through unconfigured table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void transactGetItemsOutputPassesThroughUnconfiguredTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        // The client owns TABLE; an item fetched from a different, unconfigured
        // table must pass through undecrypted.
        TransactGetItemsOutput transformed = client.transactGetItemsOutputTransform(
            TransactGetItemsOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(TransactGetItemsInput.builder()
                    .transactItems(List.of(TransactGetItem.builder()
                        .get(Get.builder()
                            .tableName("other-unconfigured-table")
                            .key(key())
                            .build())
                        .build()))
                    .build())
                .sdkOutput(TransactGetItemsOutput.builder()
                    .responses(List.of(ItemResponse.builder().item(plaintext).build()))
                    .build())
                .build()).getTransformedOutput();
        assertNotNull(transformed.getResponses(),
            "TransactGetItemsOutputTransform must return responses on " + pair);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
        //= type=test
        //# Each of these items on the original response MUST be replaced
        //# with a value that is equivalent to the resulting item.
        assertEquals(plaintext.get(SECRET).getS(),
            transformed.getResponses().get(0).getItem().get(SECRET).getS(),
            "an unconfigured-table TransactGetItems output must keep its plaintext item on " + pair);
    }
}
