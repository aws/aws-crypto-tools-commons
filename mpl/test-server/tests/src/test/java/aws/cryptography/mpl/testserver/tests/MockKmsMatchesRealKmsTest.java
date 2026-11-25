package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.KmsKeys.KMS_KEY_ARN;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.REGION;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.SECOND_KEY_ALIAS_ARN;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.SECOND_KEY_ARN;
import static aws.cryptography.mpl.testserver.tests.Materials.dataKeyOfLength;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import aws.cryptography.testserver.tests.DryRun;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Function;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.SdkField;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KmsResponse;

/**
 * Checks that MockKms replies the way real KMS does, for each KMS behavior that the keyring tests rely on.
 *
 * <p>Each behavior makes the same KMS call twice from this JVM with the AWS SDK for Java.
 * The first call goes to real KMS, with the key in {@link KmsKeys}.
 * The second goes to a MockKms that has the replies the keyring tests would give it for that call.
 * The two replies must have the same shape: the same fields, the same form of KeyId, the same plaintext length,
 * and the same error.
 * Their bytes differ, because real KMS makes random keys and its own ciphertext format.
 *
 * <p>Real KMS needs AWS credentials that allow GenerateDataKey, Encrypt and Decrypt on both keys in {@link KmsKeys}.
 * The MPL test server CI job has them.
 */
@Tag("real-kms")
class MockKmsMatchesRealKmsTest {

    private static final Map<String, String> ENCRYPTION_CONTEXT = Map.of("purpose", "mock-kms-matches-real-kms");
    /** The grant tokens that AwsKmsKeyringTest gives the keyring. */
    private static final List<String> GRANT_TOKENS = List.of("grant-token-a", "grant-token-b");
    private static final int DATA_KEY_LENGTH = 32;
    private static final int SHORT_DATA_KEY_LENGTH = 16;

    /**
     * A KMS behavior: how the keyring tests script MockKms for it, and the KMS call whose reply is compared.
     * A call can make a setup call first, such as Encrypt before Decrypt, and only its last reply is compared.
     */
    enum Behavior {
        GENERATE_DATA_KEY_FOR_KEY_ARN(
            mockKms -> mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN),
            kms -> kms.generateDataKey(r -> r
                .keyId(KMS_KEY_ARN)
                .numberOfBytes(DATA_KEY_LENGTH)
                .encryptionContext(ENCRYPTION_CONTEXT))),

        /** The reply KeyId is the ARN of the key that the alias names, not the alias. */
        GENERATE_DATA_KEY_FOR_ALIAS(
            mockKms -> mockKms.nextGenerateDataKeyReturnsDataKeyFor(SECOND_KEY_ARN),
            kms -> kms.generateDataKey(r -> r
                .keyId(SECOND_KEY_ALIAS_ARN)
                .numberOfBytes(DATA_KEY_LENGTH)
                .encryptionContext(ENCRYPTION_CONTEXT))),

        /** The keyring tests script a plaintext of the length that the keyring asked for. */
        GENERATE_DATA_KEY_HONORS_NUMBER_OF_BYTES(
            mockKms -> mockKms.nextGenerateDataKeyReturns(KMS_KEY_ARN, dataKeyOfLength(SHORT_DATA_KEY_LENGTH)),
            kms -> kms.generateDataKey(r -> r
                .keyId(KMS_KEY_ARN)
                .numberOfBytes(SHORT_DATA_KEY_LENGTH)
                .encryptionContext(ENCRYPTION_CONTEXT))),

        ENCRYPT(
            mockKms -> mockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN),
            kms -> encrypt(kms)),

        DECRYPT(
            mockKms -> {
                mockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN);
                mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
            },
            kms -> kms.decrypt(r -> r
                .keyId(KMS_KEY_ARN)
                .ciphertextBlob(encrypt(kms).ciphertextBlob())
                .encryptionContext(ENCRYPTION_CONTEXT))),

        /** Decrypt with a KeyId that is a real key, but not the key that encrypted the ciphertext. */
        DECRYPT_WITH_WRONG_KEY(
            mockKms -> {
                mockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN);
                mockKms.nextDecryptFailsWith("IncorrectKeyException");
            },
            kms -> kms.decrypt(r -> r
                .keyId(SECOND_KEY_ARN)
                .ciphertextBlob(encrypt(kms).ciphertextBlob())
                .encryptionContext(ENCRYPTION_CONTEXT))),

        GENERATE_DATA_KEY_WITH_GRANT_TOKENS(
            mockKms -> mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN),
            kms -> kms.generateDataKey(r -> r
                .keyId(KMS_KEY_ARN)
                .numberOfBytes(DATA_KEY_LENGTH)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .grantTokens(GRANT_TOKENS)));

        private final Consumer<MockKms> script;
        private final Function<KmsClient, KmsResponse> call;

        Behavior(Consumer<MockKms> script, Function<KmsClient, KmsResponse> call) {
            this.script = script;
            this.call = call;
        }
    }

    /**
     * What a test can rely on in a KMS reply.
     * {@code error} is the SDK exception and KMS error code, or null when the call succeeded.
     * The other fields are null when the call failed.
     */
    record ReplyShape(SortedSet<String> fields, String keyIdForm, Integer plaintextLength, String error) {

        static ReplyShape of(KmsResponse reply) {
            SortedSet<String> fields = new TreeSet<>();
            for (SdkField<?> field : reply.sdkFields()) {
                if (field.getValueOrDefault(reply) != null) {
                    fields.add(field.memberName());
                }
            }
            String keyId = reply.getValueForField("KeyId", String.class).orElse(null);
            Integer plaintextLength = reply.getValueForField("Plaintext", SdkBytes.class)
                .map(plaintext -> plaintext.asByteArray().length)
                .orElse(null);
            return new ReplyShape(fields, formOf(keyId), plaintextLength, null);
        }

        static ReplyShape of(KmsException error) {
            return new ReplyShape(null, null, null,
                error.getClass().getSimpleName() + " " + error.awsErrorDetails().errorCode());
        }
    }

    @ParameterizedTest(name = "[aws-kms] MockKms replies like real KMS: {0}")
    @EnumSource(Behavior.class)
    void mockKmsRepliesLikeRealKms(Behavior behavior) {
        // A dry run starts no servers and has no AWS credentials.
        assumeFalse(DryRun.enabled(), "a dry run makes no KMS calls");

        ReplyShape real;
        try (KmsClient kms = KmsClient.builder().region(Region.of(REGION)).build()) {
            real = replyShape(behavior, kms);
        }

        ReplyShape mock;
        try (MockKms mockKms = new MockKms();
                KmsClient kms = mockKmsClient(mockKms)) {
            behavior.script.accept(mockKms);
            mock = replyShape(behavior, kms);
        }

        assertEquals(real, mock, "MockKms must reply like real KMS");
    }

    private static ReplyShape replyShape(Behavior behavior, KmsClient kms) {
        try {
            return ReplyShape.of(behavior.call.apply(kms));
        } catch (KmsException e) {
            return ReplyShape.of(e);
        }
    }

    /** MockKms ignores request signatures, but the SDK needs credentials to sign one. */
    private static KmsClient mockKmsClient(MockKms mockKms) {
        return KmsClient.builder()
            .region(Region.of(REGION))
            .endpointOverride(URI.create(mockKms.endpoint()))
            .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("mock", "mock")))
            .build();
    }

    private static EncryptResponse encrypt(KmsClient kms) {
        return kms.encrypt(r -> r
            .keyId(KMS_KEY_ARN)
            .plaintext(SdkBytes.fromByteArray(dataKeyOfLength(DATA_KEY_LENGTH)))
            .encryptionContext(ENCRYPTION_CONTEXT));
    }

    /** Whether {@code keyId} is a key ARN, an alias ARN or something else. The value itself differs by key. */
    private static String formOf(String keyId) {
        if (keyId == null) {
            return null;
        }
        if (keyId.matches("arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/.+")) {
            return "key ARN";
        }
        if (keyId.matches("arn:aws:kms:[a-z0-9-]+:[0-9]{12}:alias/.+")) {
            return "alias ARN";
        }
        return "other";
    }
}
