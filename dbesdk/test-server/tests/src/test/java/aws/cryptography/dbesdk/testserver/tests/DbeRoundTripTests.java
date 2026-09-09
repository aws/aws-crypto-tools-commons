package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientOutput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Live end-to-end round-trip tests, run as <strong>cross-language pair
 * tests</strong>. For every {@code (encryptTarget, decryptTarget)} pair the
 * orchestrator launches, this builds a keyring on both targets, encrypts on
 * the encrypt target, decrypts on the decrypt target, and asserts the
 * plaintext round-trips. Because every language's DBE library wraps the same
 * DEK with the same keyring, a cross-language pair unwraps the other side's
 * EDK — the round-trip proves wire-compatible handling across implementations.
 *
 * <p>Two scenarios cover the current Feature_Catalog:
 * <ul>
 *   <li>{@code awsKms} — live AWS KMS keyring against the ESDK-shared
 *       symmetric test key (from
 *       {@link DbeTestHelpers#resolveKmsKeyArn()}). Requires AWS
 *       credentials and network access to KMS.</li>
 *   <li>{@code rawAes} — offline Raw-AES keyring with a deterministic 32-byte
 *       wrapping key. No AWS credentials required — useful when smoke-checking
 *       the wire model without hitting KMS.</li>
 * </ul>
 *
 * <p>These are the positive-path proofs that untampered bytes decrypt
 * successfully cross-language. Without them, the tamper tests could pass
 * every assertion for the wrong reason (a broken decrypt path that refuses
 * every input). The tamper tests assert that mutations are refused; these
 * tests assert that non-mutations are accepted.
 *
 * <p>The companion {@code smoke/dbesdk_round_trip_smoke_check.sh} script
 * scopes to {@code rawAesRoundTrip} for a single-server offline smoke check.
 */
class DbeRoundTripTests {

    // 32 bytes -> AES_256_GCM_IV12_TAG16. Deterministic so the test is
    // repeatable across runs.
    private static final byte[] RAW_AES_WRAPPING_KEY = new byte[] {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10,
        (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
        (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F, (byte) 0x20,
    };

    @ParameterizedTest(name = "[awsKms] round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void awsKmsRoundTrip(TargetPair pair) {
        roundTrip(pair, awsKmsConfig());
    }

    @ParameterizedTest(name = "[rawAes] round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void rawAesRoundTrip(TargetPair pair) {
        roundTrip(pair, rawAesConfig());
    }

    // ---------------------------------------------------------------------
    // Round-trip helper — CreateClient → EncryptItem → DecryptItem across the
    // encrypt/decrypt pair. Asserts the plaintext round-trips attribute-by-
    // attribute.
    // ---------------------------------------------------------------------

    private static void roundTrip(TargetPair pair, DBEClientConfig config) {
        DBESDKTestServerClient encryptClient = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        Map<String, AttributeValue> plaintext = canonicalPlaintext();

        CreateClientOutput encCreated = encryptClient.createClient(
            CreateClientInput.builder().config(config).build());
        assertNotNull(encCreated.getClientId(), "CreateClient (encrypt) returned a null clientId");

        EncryptItemOutput encrypted = encryptClient.encryptItem(
            EncryptItemInput.builder()
                .clientId(encCreated.getClientId())
                .plaintextItem(plaintext)
                .build());
        Map<String, AttributeValue> encryptedItem = encrypted.getEncryptedItem();
        assertNotNull(encryptedItem, "EncryptItem returned a null encrypted item");
        //= specification/structured-encryption/structures.md#encrypt
        //= type=test
        //# During [Encrypt Structure](encrypt-structure.md#encrypt-structure),
        //# ENCRYPT signifies that the [Terminal Value](#terminal-value) in the [Terminal Data](#terminal-data)
        //# MUST be encrypted in the resulting encrypted [Structured Data](#structured-data).
        assertNotEquals(
            plaintext.get(SECRET).getS(),
            encryptedItem.get(SECRET).getS(),
            "encrypted 'secret' attribute unexpectedly equals the plaintext value");
        //= specification/structured-encryption/structures.md#do_not_encrypt
        //= type=test
        //# During [Encrypt Structure](encrypt-structure.md#encrypt-structure)
        //# and [Decrypt Structure](decrypt-structure.md#decrypt-structure),
        //# DO_NOT_ENCRYPT signifies that the [Terminal Data](#terminal-data)
        //# MUST have an equal [Terminal Value](#terminal-value) and
        //# [Terminal Type Id](#terminal-type-id) as the the Terminal Data
        //# in the same location in the resulting encrypted [Structured Data](#structured-data).
        assertEquals(
            plaintext.get(PK).getS(),
            encryptedItem.get(PK).getS(),
            "sign-only 'PK' attribute must be preserved verbatim in the encrypted item");

        CreateClientOutput decCreated = decryptClient.createClient(
            CreateClientInput.builder().config(config).build());
        assertNotNull(decCreated.getClientId(), "CreateClient (decrypt) returned a null clientId");

        DecryptItemOutput decrypted = decryptClient.decryptItem(
            DecryptItemInput.builder()
                .clientId(decCreated.getClientId())
                .encryptedItem(encryptedItem)
                .build());
        Map<String, AttributeValue> recovered = decrypted.getPlaintextItem();
        assertNotNull(recovered, "DecryptItem returned a null plaintext item");

        for (Map.Entry<String, AttributeValue> entry : plaintext.entrySet()) {
            AttributeValue actual = recovered.get(entry.getKey());
            //= specification/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
            //= type=test
            //# - For every entry in the [input Auth List](#auth-list), other than the header and footer,
            //#   an entry MUST exist with the same key in the output Crypto List.
            assertNotNull(actual, "recovered item missing attribute '" + entry.getKey() + "'");
            assertEquals(
                entry.getValue().getS(),
                actual.getS(),
                "attribute '" + entry.getKey() + "' did not round-trip");
        }
    }

    private static DBEClientConfig awsKmsConfig() {
        return DBEClientConfig.builder()
            .logicalTableName("aws-kms-round-trip-table")
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder()
                    .kmsKeyId(DbeTestHelpers.resolveKmsKeyArn())
                    .build())
                .build())
            .build();
    }

    private static DBEClientConfig rawAesConfig() {
        return DBEClientConfig.builder()
            .logicalTableName("raw-aes-round-trip-table")
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .rawAes(RawAesKeyringConfig.builder()
                    .keyNamespace("dbesdk-test-server")
                    .keyName("round-trip-raw-aes")
                    .wrappingKey(ByteBuffer.wrap(RAW_AES_WRAPPING_KEY))
                    .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                    .build())
                .build())
            .build();
    }
}
