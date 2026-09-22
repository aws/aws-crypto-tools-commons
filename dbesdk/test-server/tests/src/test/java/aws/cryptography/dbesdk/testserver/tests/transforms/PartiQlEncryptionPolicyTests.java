package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.BatchExecuteStatementInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchExecuteStatementInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchExecuteStatementOutput;
import aws.cryptography.dbesdk.testserver.client.model.BatchExecuteStatementOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchStatementRequest;
import aws.cryptography.dbesdk.testserver.client.model.BatchStatementResponse;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteStatementInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteStatementInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteStatementOutput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteStatementOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteTransactionInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteTransactionInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteTransactionOutput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteTransactionOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ItemResponse;
import aws.cryptography.dbesdk.testserver.client.model.ParameterizedStatement;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK validate-before PartiQL transforms. The bounded property under test: <em>a PartiQL statement that
 * targets an encrypted table is rejected before any DynamoDB call, while a
 * statement that targets no configured (encrypted) table passes through
 * unchanged.</em>
 *
 * <p>DBE cannot rewrite an opaque PartiQL statement to operate over encrypted
 * attributes, so {@code ExecuteStatement} / {@code BatchExecuteStatement} /
 * {@code ExecuteTransaction} on an encrypted table must fail. The transform
 * parses the target table out of the statement text and compares it against the
 * transforms client's configured tables.
 *
 * <p>The passthrough case is the guard that keeps the rejection cases honest: a
 * transform that rejected <em>every</em> statement would pass the rejection
 * assertions for the wrong reason, so an unencrypted-table statement must be
 * accepted and returned unchanged.
 *
 * <p>Each transform runs on the pair's encrypt endpoint, so across the pair
 * matrix every language server is exercised as the target.
 */
class PartiQlEncryptionPolicyTests {

    /** A PartiQL statement targeting the encrypted test table. */
    private static final String ENCRYPTED_TABLE_STATEMENT =
        "SELECT * FROM \"" + TABLE + "\"";

    /** A PartiQL statement targeting a table that is not encryption-configured. */
    private static final String UNENCRYPTED_TABLE_STATEMENT =
        "SELECT * FROM \"other-plaintext-table\"";

    @ParameterizedTest(name = "[transform] ExecuteStatement rejects encrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeStatementRejectsEncryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executestatement
        //= type=test
        //# The request MUST fail, and the client make no network call to DynamoDB,
        //# if there exists an Item Encryptor
        //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
        //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
        //# equal to table named in the request.
        assertThrows(DBESDKClientError.class, () -> client.executeStatementInputTransform(
            ExecuteStatementInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ExecuteStatementInput.builder()
                    .statement(ENCRYPTED_TABLE_STATEMENT)
                    .build())
                .build()),
            "ExecuteStatement on an encrypted table must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[transform] ExecuteStatement passes through unencrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeStatementPassesThroughUnencryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        ExecuteStatementInput transformed = client.executeStatementInputTransform(
            ExecuteStatementInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ExecuteStatementInput.builder()
                    .statement(UNENCRYPTED_TABLE_STATEMENT)
                    .build())
                .build()).getTransformedInput();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executestatement
        //= type=test
        //# If no such Item Encryptor exists,
        //# there MUST NOT be any modification
        //# to the ExecuteStatement request.
        assertEquals(UNENCRYPTED_TABLE_STATEMENT, transformed.getStatement(),
            "an unencrypted-table statement must pass through unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchExecuteStatement rejects encrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchExecuteStatementRejectsEncryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-batchexecutestatement
        //= type=test
        //# The request MUST fail, and the client make no network call to DynamoDB,
        //# if there exists an Item Encryptor
        //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
        //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
        //# equal to table named in any of the `Statements` of the request.
        assertThrows(DBESDKClientError.class, () -> client.batchExecuteStatementInputTransform(
            BatchExecuteStatementInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(BatchExecuteStatementInput.builder()
                    .statements(List.of(BatchStatementRequest.builder()
                        .statement(ENCRYPTED_TABLE_STATEMENT)
                        .build()))
                    .build())
                .build()),
            "BatchExecuteStatement targeting an encrypted table must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchExecuteStatement passes through unencrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchExecuteStatementPassesThroughUnencryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        BatchExecuteStatementInput transformed = client.batchExecuteStatementInputTransform(
            BatchExecuteStatementInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(BatchExecuteStatementInput.builder()
                    .statements(List.of(BatchStatementRequest.builder()
                        .statement(UNENCRYPTED_TABLE_STATEMENT)
                        .build()))
                    .build())
                .build()).getTransformedInput();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-batchexecutestatement
        //= type=test
        //# If no such Item Encryptor exists,
        //# there MUST NOT be any modification
        //# to the BatchExecuteStatement request.
        assertEquals(UNENCRYPTED_TABLE_STATEMENT,
            transformed.getStatements().get(0).getStatement(),
            "an unencrypted-table batch statement must pass through unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] ExecuteTransaction rejects encrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeTransactionRejectsEncryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executetransaction
        //= type=test
        //# The request MUST fail, and the client make no network call to DynamoDB,
        //# if there exists an Item Encryptor
        //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
        //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
        //# equal to table named in any of the `TransactStatements` of the request.
        assertThrows(DBESDKClientError.class, () -> client.executeTransactionInputTransform(
            ExecuteTransactionInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ExecuteTransactionInput.builder()
                    .transactStatements(List.of(ParameterizedStatement.builder()
                        .statement(ENCRYPTED_TABLE_STATEMENT)
                        .build()))
                    .build())
                .build()),
            "ExecuteTransaction targeting an encrypted table must be rejected on " + pair);
    }

    @ParameterizedTest(name = "[transform] ExecuteTransaction passes through unencrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeTransactionPassesThroughUnencryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        ExecuteTransactionInput transformed = client.executeTransactionInputTransform(
            ExecuteTransactionInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ExecuteTransactionInput.builder()
                    .transactStatements(List.of(ParameterizedStatement.builder()
                        .statement(UNENCRYPTED_TABLE_STATEMENT)
                        .build()))
                    .build())
                .build()).getTransformedInput();
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executetransaction
        //= type=test
        //# If no such Item Encryptor exists,
        //# there MUST NOT be any modification
        //# to the ExecuteTransaction request.
        assertEquals(UNENCRYPTED_TABLE_STATEMENT,
            transformed.getTransactStatements().get(0).getStatement(),
            "an unencrypted-table transact statement must pass through unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] ExecuteStatement output passes through unencrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeStatementOutputPassesThroughUnencryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        ExecuteStatementOutput transformed = client.executeStatementOutputTransform(
            ExecuteStatementOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ExecuteStatementInput.builder()
                    .statement(UNENCRYPTED_TABLE_STATEMENT)
                    .build())
                .sdkOutput(ExecuteStatementOutput.builder()
                    .items(List.of(plaintext))
                    .build())
                .build()).getTransformedOutput();
        assertNotNull(transformed.getItems(), "ExecuteStatement output must return items on " + pair);
        assertEquals(plaintext.get(SECRET).getS(),
            transformed.getItems().get(0).get(SECRET).getS(),
            "an unencrypted-table ExecuteStatement output must keep its plaintext items on " + pair);
    }

    @ParameterizedTest(name = "[transform] ExecuteTransaction output passes through unencrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeTransactionOutputPassesThroughUnencryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        ExecuteTransactionOutput transformed = client.executeTransactionOutputTransform(
            ExecuteTransactionOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(ExecuteTransactionInput.builder()
                    .transactStatements(List.of(ParameterizedStatement.builder()
                        .statement(UNENCRYPTED_TABLE_STATEMENT)
                        .build()))
                    .build())
                .sdkOutput(ExecuteTransactionOutput.builder()
                    .responses(List.of(ItemResponse.builder().item(plaintext).build()))
                    .build())
                .build()).getTransformedOutput();
        assertNotNull(transformed.getResponses(),
            "ExecuteTransaction output must return responses on " + pair);
        assertEquals(plaintext.get(SECRET).getS(),
            transformed.getResponses().get(0).getItem().get(SECRET).getS(),
            "an unencrypted-table ExecuteTransaction output must keep its plaintext item on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchExecuteStatement output passes through unencrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchExecuteStatementOutputPassesThroughUnencryptedTable(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        BatchExecuteStatementOutput transformed = client.batchExecuteStatementOutputTransform(
            BatchExecuteStatementOutputTransformInput.builder()
                .clientId(clientId)
                .originalInput(BatchExecuteStatementInput.builder()
                    .statements(List.of(BatchStatementRequest.builder()
                        .statement(UNENCRYPTED_TABLE_STATEMENT)
                        .build()))
                    .build())
                .sdkOutput(BatchExecuteStatementOutput.builder()
                    .responses(List.of(BatchStatementResponse.builder()
                        .tableName("other-plaintext-table")
                        .item(plaintext)
                        .build()))
                    .build())
                .build()).getTransformedOutput();
        assertNotNull(transformed.getResponses(),
            "BatchExecuteStatement output must return responses on " + pair);
        assertEquals(plaintext.get(SECRET).getS(),
            transformed.getResponses().get(0).getItem().get(SECRET).getS(),
            "an unencrypted-table BatchExecuteStatement output must keep its plaintext item on " + pair);
    }
}
