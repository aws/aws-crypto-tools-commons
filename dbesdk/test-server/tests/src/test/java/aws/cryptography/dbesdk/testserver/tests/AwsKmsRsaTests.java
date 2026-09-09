package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEAlgorithmSuiteId;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * AWS-KMS-RSA keyring behavior. Cohesive property: an item encrypted under an
 * {@code AwsKmsRsa} keyring — whose data key is wrapped client-side with an
 * asymmetric RSA public key and unwrapped via {@code kms:Decrypt} — round-trips
 * across the full cross-language pair matrix, and the asymmetric wrap is genuinely
 * in effect (a symmetric {@code AwsKms} keyring cannot decrypt an RSA-wrapped
 * item).
 *
 * <p>Exercises a live asymmetric KMS key (RSA_2048, ENCRYPT_DECRYPT). The public
 * key is fetched server-side once via {@code kms:GetPublicKey} at CreateClient
 * time (the config carries no inline key), so the round-trip proves the whole
 * fetch → client-side RSA wrap → KMS unwrap path cross-language.
 *
 * <p>Distinct from {@link DbeRoundTripTests} (symmetric {@code AwsKms} /
 * {@code RawAes}), {@link AwsKmsMrkTests} (MRK), and {@link AwsKmsHierarchicalTests}
 * (branch-key hierarchy).
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #rsaKeyringRoundTripPreservesPlaintext} — RSA keyring both ends</li>
 *   <li>{@link #rsaEncryptedItemIsNotDecryptableByPlainKmsKeyring} — asymmetric isolation</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 2 assertions × pairs²}.
 */
class AwsKmsRsaTests {

    // A live asymmetric RSA_2048 (ENCRYPT_DECRYPT) KMS key in the test account.
    private static final String RSA_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/624eeb76-f04e-41e5-a66b-359ff89862a3";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /**
     * Build a DBE client on {@code client} backed by an {@code AwsKmsRsa} keyring
     * over the live RSA key, with no inline public key (the server fetches it via
     * {@code kms:GetPublicKey}). The AwsKmsRsa keyring is incompatible with an
     * asymmetric-signing (ECDSA) suite, so a symmetric-signing (SYMSIG) suite is
     * used; {@code encryptionAlgorithm} is supplied explicitly (required by the
     * Java server, defaulted by the others).
     */
    private static String newRsaClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .algorithmSuiteId(
                DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
            .keyring(Keyring.builder()
                .awsKmsRsa(AwsKmsRsaKeyringConfig.builder()
                    .kmsKeyId(RSA_KEY_ARN)
                    .encryptionAlgorithm(KmsRsaEncryptionAlgorithm.RSAES_OAEP_SHA_256)
                    .build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    @ParameterizedTest(name = "AwsKmsRsa keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void rsaKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newRsaClient(encryptClient);
        String decryptClientId = newRsaClient(decryptClient);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("rsa", decrypted, pair);
    }

    /**
     * An RSA-wrapped item's data key is protected by the asymmetric key, not the
     * symmetric item key, so a plain {@code AwsKms} keyring MUST NOT be able to
     * decrypt it — proving the RSA wrap is actually in effect.
     */
    @ParameterizedTest(name = "RSA-encrypted item is not decryptable by a plain KMS keyring {0}")
    @MethodSource("testPairs")
    void rsaEncryptedItemIsNotDecryptableByPlainKmsKeyring(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newRsaClient(encryptClient);
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, standardActions(), java.util.List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptClientId).encryptedItem(item).build()));
    }
}
