package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * AWS-KMS-MRK keyring behavior. Cohesive property: an item encrypted under an
 * {@code AwsKmsMrk} keyring round-trips, and — for a single key ARN — the MRK
 * keyring and the standard {@code AwsKms} keyring are mutually
 * interoperable. That interoperability is the reason the MRK keyring exists:
 * an MRK keyring built on a key's ARN in one region can decrypt what a plain
 * KMS keyring on the same key wrote, and vice versa, so a caller can migrate
 * between the two without a re-encrypt.
 *
 * <p>The shared test key is a single-region symmetric key, so the cross-region
 * replica dimension of MRK is out of scope here (it needs an actual multi-Region
 * key); what is exercised is the same-key MRK/KMS interoperability and the MRK
 * keyring's own round-trip, across the full cross-language pair matrix.
 *
 * <p>Distinct from {@link DbeRoundTripTests}, which covers the plain
 * {@code AwsKms} and {@code RawAes} keyrings.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #mrkKeyringRoundTripPreservesPlaintext} — MRK keyring both ends</li>
 *   <li>{@link #mrkEncryptedItemDecryptsUnderAwsKmsKeyring} — MRK encrypt → plain-KMS decrypt</li>
 *   <li>{@link #awsKmsEncryptedItemDecryptsUnderMrkKeyring} — plain-KMS encrypt → MRK decrypt</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 3 assertions × pairs²}.
 */
class AwsKmsMrkTests {

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /**
     * Build a DBE client on {@code client} backed by an {@code AwsKmsMrk}
     * keyring pinned to {@link DbeTestHelpers#resolveKmsKeyArn()}, using the
     * standard v2 schema. Mirrors {@link DbeTestHelpers#newKmsClient} but with
     * the MRK keyring variant.
     */
    private static String newMrkClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKmsMrk(AwsKmsMrkKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .build();
        return client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
    }

    @ParameterizedTest(name = "MRK keyring round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void mrkKeyringRoundTripPreservesPlaintext(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newMrkClient(encryptClient);
        String decryptClientId = newMrkClient(decryptClient);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("mrk", decrypted, pair);
    }

    /**
     * An item encrypted with an {@code AwsKmsMrk} keyring must decrypt under a
     * plain {@code AwsKms} keyring pinned to the same key ARN.
     */
    @ParameterizedTest(name = "MRK-encrypted item decrypts under AwsKms keyring {0}")
    @MethodSource("testPairs")
    void mrkEncryptedItemDecryptsUnderAwsKmsKeyring(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newMrkClient(encryptClient);
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, standardActions(), java.util.List.of());
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("mrk->kms", decrypted, pair);
    }

    /**
     * An item encrypted with a plain {@code AwsKms} keyring must decrypt under
     * an {@code AwsKmsMrk} keyring pinned to the same key ARN.
     */
    @ParameterizedTest(name = "AwsKms-encrypted item decrypts under MRK keyring {0}")
    @MethodSource("testPairs")
    void awsKmsEncryptedItemDecryptsUnderMrkKeyring(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId =
            newKmsClient(encryptClient, TABLE, PK, standardActions(), java.util.List.of());
        String decryptClientId = newMrkClient(decryptClient);
        Map<String, AttributeValue> item =
            encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("kms->mrk", decrypted, pair);
    }
}
