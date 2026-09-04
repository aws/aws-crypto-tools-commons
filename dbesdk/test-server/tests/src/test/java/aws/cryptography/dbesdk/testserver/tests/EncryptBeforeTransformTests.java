package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.FOOT;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInput;
import aws.cryptography.dbesdk.testserver.client.model.PutItemInputTransformInput;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the DDB SDK transform round-trip (§0.3.3, core
 * encrypt-before / decrypt-after). This is the transform-surface dual of
 * {@link DbeRoundTripTests}: instead of the item-encryptor {@code EncryptItem}
 * / {@code DecryptItem}, it drives {@code PutItemInputTransform} (encrypt an
 * item as it would be written by a {@code PutItem}) and
 * {@code GetItemOutputTransform} (decrypt an item as it would be returned by a
 * {@code GetItem}).
 *
 * <p>The bounded property under test: <em>a PutItem input transformed by one
 * language's transforms client is decrypted back to the original plaintext by
 * another language's GetItem output transform.</em> Because both sides build a
 * transforms client over the same AWS-KMS keyring and the same table crypto
 * config, a cross-language pair proves the transform surface produces and
 * consumes a wire-compatible encrypted item, exactly as the item-encryptor
 * round-trip does for {@code EncryptItem} / {@code DecryptItem}.
 *
 * <p>No real DynamoDB is involved: {@code PutItemInputTransform} returns the
 * encrypted item it would have written, and that item is fed straight into
 * {@code GetItemOutputTransform} as the item a {@code GetItem} would have
 * returned — the same technique the DBE library's own transform unit tests use.
 *
 * <p>Later sub-rounds extend §0.3.3 with the remaining encrypt-before APIs
 * (BatchWrite / TransactWrite / Update / Delete), the remaining decrypt-after
 * APIs (Scan / Query / BatchGet / TransactGet), PartiQL rejection, passthrough
 * guards, and the beacon rewrite.
 */
class EncryptBeforeTransformTests {

    @ParameterizedTest(name = "[transform] PutItemInputTransform encrypts {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putItemInputTransformEncryptsItem(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());

        Map<String, AttributeValue> encrypted =
            putItemInputTransform(encryptClient, canonicalPlaintext());

        assertTrue(encrypted.containsKey(HEAD),
            "transformed PutItem input must carry the DBE header attribute on " + pair);
        assertTrue(encrypted.containsKey(FOOT),
            "transformed PutItem input must carry the DBE footer attribute on " + pair);
        assertNotNull(encrypted.get(SECRET).getB(),
            "ENCRYPT_AND_SIGN 'secret' must become a binary value on " + pair);
        assertNull(encrypted.get(SECRET).getS(),
            "ENCRYPT_AND_SIGN 'secret' must not retain its plaintext string on " + pair);
        assertEquals("item-1", encrypted.get(PK).getS(),
            "signed partition key 'PK' must be preserved verbatim on " + pair);
    }

    @ParameterizedTest(name = "[transform] Put→Get transform round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void putThenGetOutputTransformRoundTripsPlaintext(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> encrypted = putItemInputTransform(encryptClient, plaintext);

        String decryptClientId = createTransformsClient(decryptClient);
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

    // ---------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------

    /** Build a transforms client on {@code client} over the shared AWS-KMS key. */
    private static String createTransformsClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder()
                    .kmsKeyId(DbeTestHelpers.resolveKmsKeyArn())
                    .build())
                .build())
            .build();
        return client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(TABLE).build())
            .getClientId();
    }

    /**
     * Create a transforms client on {@code client} and run PutItemInputTransform
     * on {@code plaintext}, returning the encrypted item.
     */
    private static Map<String, AttributeValue> putItemInputTransform(
            DBESDKTestServerClient client, Map<String, AttributeValue> plaintext) {
        String clientId = createTransformsClient(client);
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
}
