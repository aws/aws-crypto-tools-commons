package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEAlgorithmSuiteId;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.TransformsTableConfig;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for a multi-table DDB SDK transforms client. The bounded property under test: <em>when one transforms client is
 * bound to several tables, each table's crypto config — in particular its
 * {@code algorithmSuiteId} — is applied independently and never cross-copied
 * from another table.</em>
 *
 * <p>Regression coverage for DBE fix ff3acacc (aws-database-encryption-sdk-dynamodb
 * #1474, "ensure algorithmSuite is properly copied in getTableConfig"): the
 * per-table {@code algorithmSuiteId} was being dropped when a
 * {@code DynamoDbTablesEncryptionConfig} was assembled, so a table configured
 * with a non-default suite silently fell back to the default. Before that fix
 * this test fails; after it, it passes.
 *
 * <p>The observable signal is the ECDSA public key in the item header's
 * Encryption Context. The default suite
 * ({@code ALG_..._ECDSA_P384_SYMSIG_HMAC_SHA384}) signs each item with
 * ECDSA-P384 and writes an {@code aws-crypto-public-key} entry into the header
 * EC; the symmetric-only suite
 * ({@code ALG_..._SYMSIG_HMAC_SHA384}) has no ECDSA signature and writes no such
 * entry. So one client bound to a default-suite table and a symmetric-suite
 * table must produce items whose headers differ on exactly that entry.
 *
 * <p>The two tests are each other's guard: the default-suite table proves the
 * public-key signal is present when it should be (so its absence is meaningful),
 * and the symmetric-suite table proves the per-table suite was honored (its
 * absence is the regression signal — a dropped suite would fall back to the
 * ECDSA default and the entry would wrongly appear).
 *
 * <p>Each transform runs on the pair's encrypt endpoint, so across the pair
 * matrix every language server is exercised as the target.
 */
class MultiTableConfigTests {

    /** A second physical table, bound in the same transforms client as {@link #TABLE}. */
    private static final String TABLE_B = "dbesdk-test-server-table-b";

    /** The ECDSA public-key entry the signing (default) suite writes into the header EC. */
    private static final String AWS_CRYPTO_PUBLIC_KEY = "aws-crypto-public-key";

    /**
     * Build a transforms client bound to two tables: {@link #TABLE} on the
     * default (ECDSA-signing) suite and {@link #TABLE_B} on the symmetric-only
     * suite.
     */
    private static String twoTableClient(DBESDKTestServerClient client) {
        return client.createTransformsClient(
            CreateTransformsClientInput.builder()
                .config(DbeTestHelpers.transformsConfig(TABLE, null))
                .tableName(TABLE)
                .additionalTables(List.of(TransformsTableConfig.builder()
                    .tableName(TABLE_B)
                    .config(DbeTestHelpers.transformsConfig(TABLE_B,
                        DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384))
                    .build()))
                .build())
            .getClientId();
    }

    /** Encrypt {@link DbeTestHelpers#canonicalPlaintext()} against {@code table} and return the header EC. */
    private static Map<String, String> headerEcAfterPut(
            DBESDKTestServerClient client, String clientId, String table) {
        PutItemInput encrypted = client.putItemInputTransform(
            PutItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(PutItemInput.builder()
                    .tableName(table)
                    .item(DbeTestHelpers.canonicalPlaintext())
                    .build())
                .build()).getTransformedInput();
        AttributeValue header = encrypted.getItem().get(HEAD);
        return DbeTestHelpers.parseHeaderEncryptionContext(DbeTestHelpers.bytesOf(header));
    }

    @ParameterizedTest(name = "[transform] default-suite table writes the ECDSA public key {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void defaultSuiteTableWritesEcdsaPublicKey(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = twoTableClient(client);
        Map<String, String> ec = headerEcAfterPut(client, clientId, TABLE);
        assertTrue(ec.containsKey(AWS_CRYPTO_PUBLIC_KEY),
            "the default (ECDSA-signing) suite table must write '" + AWS_CRYPTO_PUBLIC_KEY
                + "' into the header EC on " + pair);
    }

    @ParameterizedTest(name = "[transform] symmetric-suite table honors its own suite {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void symmetricSuiteTableHonorsItsOwnSuite(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = twoTableClient(client);
        Map<String, String> ec = headerEcAfterPut(client, clientId, TABLE_B);
        //= specification/dynamodb-encryption-client/ddb-sdk-integration.md#dynamodb-table-encryption-configs
        //= type=test
        //# During initialization, this client MUST construct a
        //# [DynamoDb Item Encryptor](./ddb-table-encryption-config.md)
        //# per configured table, using these table encryption configs.
        assertFalse(ec.containsKey(AWS_CRYPTO_PUBLIC_KEY),
            "the symmetric-only suite table must NOT write '" + AWS_CRYPTO_PUBLIC_KEY
                + "' — its per-table algorithmSuiteId must not fall back to the ECDSA default"
                + " (regression ff3acacc) on " + pair);
    }
}
