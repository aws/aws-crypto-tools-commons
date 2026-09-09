package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.PlaintextOverride;
import aws.cryptography.dbesdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Plaintext policy (§0.3.7). {@code PlaintextOverride} on the item encryptor
 * governs whether UNENCRYPTED items are written and/or read — the mechanism for
 * migrating a plaintext table onto client-side encryption. Unlike the legacy
 * DDBEC adapter (which needs a legacy encryptor instance that only Java has),
 * {@code PlaintextOverride} is a plain config enum implemented by all three
 * libraries, so these run on the full cross-language pair matrix.
 *
 * <ul>
 *   <li>{@code FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ} — EncryptItem writes
 *       the item through as plaintext (no header, secret left cleartext).</li>
 *   <li>{@code FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ} — DecryptItem reads
 *       an unencrypted item back unchanged.</li>
 *   <li>default ({@code FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ}) —
 *       DecryptItem rejects an unencrypted item.</li>
 * </ul>
 *
 * <p>Uses an offline Raw-AES keyring: the config requires a keyring, but the
 * plaintext-write path never invokes it and the plaintext-read path reads an
 * item that carries no wrapped key, so no KMS traffic is needed.
 */
class PlaintextPolicyTests {

    private static final byte[] RAW_AES_WRAPPING_KEY = new byte[] {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10,
        (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
        (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F, (byte) 0x20,
    };

    @ParameterizedTest(name = "[plaintext] FORCE_PLAINTEXT_WRITE writes an unencrypted item {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void forcePlaintextWriteProducesUnencryptedItem(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        String clientId = client.createClient(CreateClientInput.builder()
            .config(plaintextConfig(PlaintextOverride.FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ))
            .build()).getClientId();
        Map<String, AttributeValue> written = client.encryptItem(EncryptItemInput.builder()
            .clientId(clientId)
            .plaintextItem(plaintext)
            .build()).getEncryptedItem();

        //= specification/dynamodb-encryption-client/encrypt-item.md#behavior
        //= type=test
        //# If a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy) of
        //# `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` is specified,
        //# this operation MUST NOT encrypt the input item,
        //# and MUST passthrough that item as the output.
        assertFalse(written.containsKey("aws_dbe_head"),
            "FORCE_PLAINTEXT_WRITE must not add the aws_dbe_head header on " + pair);
        assertEquals(plaintext.get(SECRET).getS(), written.get(SECRET).getS(),
            "FORCE_PLAINTEXT_WRITE must leave the secret attribute as plaintext on " + pair);
    }

    @ParameterizedTest(name = "[plaintext] ALLOW_PLAINTEXT_READ reads an unencrypted item {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void allowPlaintextReadReturnsUnencryptedItem(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        String clientId = client.createClient(CreateClientInput.builder()
            .config(plaintextConfig(PlaintextOverride.FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ))
            .build()).getClientId();
        Map<String, AttributeValue> recovered = client.decryptItem(DecryptItemInput.builder()
            .clientId(clientId)
            .encryptedItem(plaintext)
            .build()).getPlaintextItem();

        //= specification/dynamodb-encryption-client/decrypt-item.md#behavior
        //= type=test
        //# If a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy) of
        //# `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` or `FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` is specified,
        //# and the input item [is a plaintext item](#determining-plaintext-items)
        //# this operation MUST NOT decrypt the input item,
        //# and MUST passthrough that item as the output.
        for (Map.Entry<String, AttributeValue> entry : plaintext.entrySet()) {
            AttributeValue actual = recovered.get(entry.getKey());
            assertNotNull(actual, "ALLOW_PLAINTEXT_READ dropped attribute '" + entry.getKey()
                + "' on " + pair);
            assertEquals(entry.getValue().getS(), actual.getS(),
                "plaintext attribute '" + entry.getKey() + "' did not pass through on " + pair);
        }
    }

    @ParameterizedTest(name = "[plaintext] default policy rejects reading an unencrypted item {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void defaultPolicyRejectsReadingPlaintextItem(TargetPair pair) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        String clientId = client.createClient(CreateClientInput.builder()
            .config(plaintextConfig(null))
            .build()).getClientId();

        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#plaintext-policy
        //= type=test
        //= reason=with no override the default attempts to decrypt the plaintext item, which has no header and fails
        //# If not specified, encryption and decryption MUST behave according to `FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ`.
        assertThrows(DBESDKClientError.class, () ->
            client.decryptItem(DecryptItemInput.builder()
                .clientId(clientId)
                .encryptedItem(canonicalPlaintext())
                .build()),
            "the default policy (FORBID_PLAINTEXT_READ) must reject an unencrypted item on " + pair);
    }

    /** Item-encryptor config over an offline Raw-AES keyring, with an optional plaintext override. */
    private static DBEClientConfig plaintextConfig(PlaintextOverride override) {
        DBEClientConfig.Builder builder = DBEClientConfig.builder()
            .logicalTableName("plaintext-policy-table")
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .rawAes(RawAesKeyringConfig.builder()
                    .keyNamespace("dbesdk-test-server")
                    .keyName("plaintext-policy-raw-aes")
                    .wrappingKey(ByteBuffer.wrap(RAW_AES_WRAPPING_KEY))
                    .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                    .build())
                .build());
        if (override != null) {
            builder.plaintextOverride(override);
        }
        return builder.build();
    }
}
