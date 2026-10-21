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
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsMultiKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * AWS-KMS multi-keyring LIVE cross-language interop — a writer on runtime A
 * encrypts with an {@code AwsKmsMultiKeyring} (a generator KMS key plus one
 * additional KMS key), producing one Encrypted Data Key per key. A reader on
 * runtime B then decrypts under EACH key alone, proving both EDKs are
 * independently decryptable across languages.
 */
class AwsKmsMultiKeyringInteropTests {

    // Generator: the shared symmetric item key. Additional: a dedicated symmetric
    // key provisioned for this test (alias/dbesdk-test-server-multi-additional).
    private static final String GENERATOR_KEY = resolveKmsKeyArn();
    private static final String ADDITIONAL_KEY =
        "arn:aws:kms:us-west-2:370957321024:key/6407c2c6-4a5a-46cc-940e-7c1f2dcedfe9";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
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

    private static Keyring multiKmsKeyring() {
        return Keyring.builder()
            .awsKmsMultiKeyring(AwsKmsMultiKeyringConfig.builder()
                .generator(GENERATOR_KEY)
                .kmsKeyIds(List.of(ADDITIONAL_KEY))
                .build())
            .build();
    }

    private static Keyring singleKmsKeyring(String kmsKeyId) {
        return Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(kmsKeyId).build())
            .build();
    }

    @ParameterizedTest(name = "AwsKmsMulti keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void multiKmsKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newClient(encryptClient, multiKmsKeyring());
        String decryptClientId = newClient(decryptClient, multiKmsKeyring());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("aws-kms-multi", decrypted, pair);
    }

    @ParameterizedTest(name = "each KMS key alone decrypts the multi-encrypted item {0}")
    @MethodSource("testPairs")
    void eachKmsKeyAloneDecryptsMultiEncryptedItem(TargetPair pair) {
        FeatureGate.require(Set.of("aws-kms"), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newClient(encryptClient, multiKmsKeyring());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());

        String viaGeneratorId = newClient(decryptClient, singleKmsKeyring(GENERATOR_KEY));
        DecryptItemOutput viaGenerator = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(viaGeneratorId).encryptedItem(item).build());
        assertPlaintextPreserved("multi -> generator key", viaGenerator, pair);

        String viaAdditionalId = newClient(decryptClient, singleKmsKeyring(ADDITIONAL_KEY));
        DecryptItemOutput viaAdditional = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(viaAdditionalId).encryptedItem(item).build());
        assertPlaintextPreserved("multi -> additional key", viaAdditional, pair);
    }
}
