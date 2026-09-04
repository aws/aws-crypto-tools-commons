package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.BatchExecuteStatementInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchExecuteStatementInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.BatchStatementRequest;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteStatementInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteStatementInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteTransactionInput;
import aws.cryptography.dbesdk.testserver.client.model.ExecuteTransactionInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ParameterizedStatement;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK validate-before PartiQL transforms
 * (§0.3.3). The bounded property under test: <em>a PartiQL statement that
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
class PartiQlRejectionTests {

    /** A PartiQL statement targeting the encrypted test table. */
    private static final String ENCRYPTED_TABLE_STATEMENT =
        "SELECT * FROM \"" + TABLE + "\"";

    /** A PartiQL statement targeting a table that is not encryption-configured. */
    private static final String UNENCRYPTED_TABLE_STATEMENT =
        "SELECT * FROM \"other-plaintext-table\"";

    @ParameterizedTest(name = "[transform] ExecuteStatement rejects encrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeStatementRejectsEncryptedTable(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
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
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        ExecuteStatementInput transformed = client.executeStatementInputTransform(
            ExecuteStatementInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(ExecuteStatementInput.builder()
                    .statement(UNENCRYPTED_TABLE_STATEMENT)
                    .build())
                .build()).getTransformedInput();
        assertEquals(UNENCRYPTED_TABLE_STATEMENT, transformed.getStatement(),
            "an unencrypted-table statement must pass through unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] BatchExecuteStatement rejects encrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void batchExecuteStatementRejectsEncryptedTable(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
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

    @ParameterizedTest(name = "[transform] ExecuteTransaction rejects encrypted table {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void executeTransactionRejectsEncryptedTable(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
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
}
