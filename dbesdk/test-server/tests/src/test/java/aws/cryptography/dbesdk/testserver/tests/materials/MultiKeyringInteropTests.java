package aws.cryptography.dbesdk.testserver.tests.materials;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.MultiKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Multi-keyring LIVE cross-language interop — a writer on runtime A encrypts with
 * a multi-keyring (an AWS-KMS generator plus a Raw-AES child), which produces one
 * Encrypted Data Key per member. A reader on runtime B then decrypts the same
 * item under EACH member keyring alone, proving every member's EDK is
 * independently decryptable across languages.
 */
class MultiKeyringInteropTests {

    // Deterministic 32-byte raw-AES wrapping key (AES_256_GCM_IV12_TAG16).
    private static final byte[] RAW_AES_WRAPPING_KEY = new byte[] {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10,
        (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
        (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F, (byte) 0x20,
    };

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static Keyring awsKmsKeyring() {
        return Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
            .build();
    }

    private static Keyring rawAesKeyring() {
        return Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace("dbesdk-test-server")
                .keyName("multi-child-raw-aes")
                .wrappingKey(ByteBuffer.wrap(RAW_AES_WRAPPING_KEY))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
    }

    private static String newClient(DBESDKTestServerClient client, Keyring keyring) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(keyring)
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    private static Keyring multiKeyring() {
        return Keyring.builder()
            .multi(MultiKeyringConfig.builder()
                .generator(awsKmsKeyring())
                .childKeyrings(List.of(rawAesKeyring()))
                .build())
            .build();
    }

    @ParameterizedTest(name = "multi keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void multiKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms", "raw-aes"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newClient(encryptClient, multiKeyring());
        String decryptClientId = newClient(decryptClient, multiKeyring());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("multi", decrypted, pair);
    }

    @ParameterizedTest(name = "each member keyring alone decrypts the multi-encrypted item {0}")
    @MethodSource("testPairs")
    void eachMemberKeyringAloneDecryptsMultiEncryptedItem(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms", "raw-aes"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newClient(encryptClient, multiKeyring());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());

        // The generator (AWS-KMS) alone decrypts its EDK.
        String kmsOnlyId = newClient(decryptClient, awsKmsKeyring());
        DecryptItemOutput viaKms = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(kmsOnlyId).encryptedItem(item).build());
        assertPlaintextPreserved("multi -> aws-kms child", viaKms, pair);

        // The Raw-AES child alone decrypts its EDK.
        String rawAesOnlyId = newClient(decryptClient, rawAesKeyring());
        DecryptItemOutput viaRawAes = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(rawAesOnlyId).encryptedItem(item).build());
        assertPlaintextPreserved("multi -> raw-aes child", viaRawAes, pair);
    }
}
