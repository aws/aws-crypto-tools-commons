package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.KeyringTestHelpers.assertKeyringRoundTrips;
import static aws.cryptography.mpl.testserver.tests.KeyringTestHelpers.assertOnDecryptFails;
import static aws.cryptography.mpl.testserver.tests.KeyringTestHelpers.assertOnEncryptFails;
import static aws.cryptography.mpl.testserver.tests.KeyringTestHelpers.bytes;
import static aws.cryptography.mpl.testserver.tests.KeyringTestHelpers.forEachLanguageServer;
import static aws.cryptography.mpl.testserver.tests.KeyringTestHelpers.onEncrypt;
import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_CONFIGURATION_ERROR;
import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_MATERIALS_ERROR;
import static aws.cryptography.mpl.testserver.tests.MplErrors.NO_MATCHING_DATA_KEY_ERROR;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CreateAwsKmsKeyringInput;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.KmsClientConfig;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.mpl.testserver.client.model.OnDecryptInput;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.KmsInputs;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for the AWS KMS keyring in aws-kms-keyring.md.
 * This is the keyring for one KMS key, not the discovery or multi-Region (MRK) keyrings.
 *
 * <p>Each test runs once for each language.
 * The test sends keyring calls, such as OnEncrypt, to that language's MPL.
 * Each language has a small server that receives the calls over HTTP and passes them to its MPL.
 *
 * <p>Most tests give the keyring a KMS client that points at {@link FakeKms}.
 * FakeKms sends back the replies that the test set up, and records each request.
 * So a test can send the keyring a bad reply, or check exactly what the keyring asked KMS.
 * Creating a keyring makes no KMS call.
 * The tests that use {@code realKmsClient} call real KMS.
 * For those, every language's server needs AWS credentials that allow GenerateDataKey, Encrypt and Decrypt on KMS_KEY_ARN.
 */
public class AwsKmsKeyringTest {

    private static final String AWS_KMS_FEATURE = "aws-kms";

    // The KMS key in the CI-resources account 370957321024 that the
    // hierarchical keyring tests also use.
    // THIS IS A TESTING RESOURCE. DO NOT USE IT IN A PRODUCTION ENVIRONMENT.
    private static final String REGION = "us-west-2";
    private static final String ACCOUNT = "370957321024";
    private static final String KEY_ID = "9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String KMS_KEY_ARN = arn("key/" + KEY_ID);
    private static final String KMS_KEY_RESOURCE = "KmsKey:" + KMS_KEY_ARN;
    private static final String ALIAS_ARN = arn("alias/x");
    /** A well-formed key ARN for a key other than KMS_KEY_ARN. */
    private static final String OTHER_KEY_ARN = arn("key/00000000-0000-0000-0000-000000000000");
    private static final String OTHER_REGION = "us-east-2";

    private static final String PROVIDER_ID = "aws-kms";
    private static final List<String> GRANT_TOKENS = List.of("grant-token-a", "grant-token-b");

    /** An algorithm suite that does not sign, so the materials hold no signing key. */
    private static final AlgorithmSuiteId ALGORITHM_SUITE = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
    private static final int DATA_KEY_LENGTH = 32;

    private static final Map<String, String> ENCRYPTION_CONTEXT = Map.of("purpose", "aws-kms-keyring-test");

    /** The error code that real KMS returns for a key it cannot find. FakeKms replies with it to make a call fail. */
    private static final String KMS_ERROR_CODE = "NotFoundException";

    /** The error for a KMS call that failed with {@link #KMS_ERROR_CODE}. */
    private static final ExpectedError KMS_CALL_FAILED_ERROR = ExpectedError.builder()
        .kind("ResourceNotFound")
        .service("kms")
        .resource(KMS_KEY_RESOURCE)
        .code(KMS_ERROR_CODE)
        .build();

    /** The error for a KMS reply that the keyring rejects, such as a bad KeyId or a plaintext of the wrong length. */
    private static final ExpectedError REJECTED_KMS_REPLY_ERROR = ExpectedError.builder()
        .kind("Service")
        .service("kms")
        .resource(KMS_KEY_RESOURCE)
        .build();

    /**
     * The error for a real KMS call through a us-east-2 KMS client.
     * The kind is not checked, because it depends on what KMS in us-east-2 says about a us-west-2 key.
     */
    private static final ExpectedError WRONG_REGION_KMS_ERROR = ExpectedError.builder()
        .service("kms")
        .resource(KMS_KEY_RESOURCE)
        .build();

    /** The error for an aws-kms EDK whose provider info is not a key ARN. */
    private static final ExpectedError INVALID_PROVIDER_INFO_ERROR = ExpectedError.builder()
        .kind("Cryptographic")
        .build();

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[aws-kms] construction without a key id fails {0}")
    @MethodSource("targets")
    void constructionWithoutKeyIdFails(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS key identifier
        // Accepts an AWS KMS key identifier
        assertUsableKeyring(mpl, KMS_KEY_ARN, List.of());
        // Rejects a missing AWS KMS key identifier
        MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsClient(realKmsClient(REGION))
            .build()));
        MplErrors.expectError(languageServer, error).matches(INVALID_CONFIGURATION_ERROR);
    }

    @ParameterizedTest(name = "[aws-kms] construction without a KMS client fails {0}")
    @MethodSource("targets")
    void constructionWithoutKmsClientFails(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS SDK client
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS SDK client MUST NOT be null.
        // Accepts an AWS KMS client
        assertUsableKeyring(mpl, KMS_KEY_ARN, List.of());
        // Rejects a missing AWS KMS client
        KnownBugGate.gateDeclared("aws-kms-keyring-accepts-missing-kms-client", languageServer,
            () -> {
                MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.createAwsKmsKeyring(
                    CreateAwsKmsKeyringInput.builder()
                        .kmsKeyId(KMS_KEY_ARN)
                        .build()));
                MplErrors.expectError(languageServer, error).matches(INVALID_CONFIGURATION_ERROR);
            });
    }

    static Stream<Arguments> validGrantTokenListsByLanguageServer() {
        return forEachLanguageServer(KmsInputs.validGrantTokenLists());
    }

    @ParameterizedTest(name = "[aws-kms] construction accepts {0} {1}")
    @MethodSource("validGrantTokenListsByLanguageServer")
    void constructionAcceptsGrantTokens(Example<List<String>> grantTokens, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MAY provide a list of Grant Tokens
        assertUsableKeyring(mpl, KMS_KEY_ARN, grantTokens.value());
    }

    static Stream<Arguments> invalidGrantTokenListsByLanguageServer() {
        return forEachLanguageServer(KmsInputs.invalidGrantTokenLists());
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects {0} {1}")
    @MethodSource("invalidGrantTokenListsByLanguageServer")
    void constructionRejectsInvalidGrantTokens(Example<List<String>> grantTokens,
            LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        // Accepts valid grant tokens
        assertUsableKeyring(mpl, KMS_KEY_ARN, GRANT_TOKENS);
        // Rejects invalid grant tokens
        MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKmsClient(REGION))
            .grantTokens(grantTokens.value())
            .build()));
        MplErrors.expectError(languageServer, error).matches(INVALID_CONFIGURATION_ERROR);
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects an empty key id {0}")
    @MethodSource("targets")
    void constructionRejectsEmptyKeyId(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST NOT be null or empty.
        // Accepts non-empty AWS KMS key identifier
        assertUsableKeyring(mpl, KMS_KEY_ARN, List.of());
        // Rejects empty AWS KMS key identifier
        MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId("")
            .kmsClient(realKmsClient(REGION))
            .build()));
        MplErrors.expectError(languageServer, error).matches(INVALID_CONFIGURATION_ERROR);
    }

    static Stream<Arguments> invalidKmsIdentifiersByLanguageServer() {
        return forEachLanguageServer(KmsInputs.invalidKmsIdentifiers(KMS_KEY_ARN));
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects a key id with {0} {1}")
    @MethodSource("invalidKmsIdentifiersByLanguageServer")
    void constructionRejectsMalformedKeyId(Example<String> malformed, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        // Accepts valid AWS KMS key identifier
        assertUsableKeyring(mpl, KMS_KEY_ARN, List.of());
        // Rejects malformed AWS KMS key identifier
        MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(malformed.value())
            .kmsClient(realKmsClient(REGION))
            .build()));
        MplErrors.expectError(languageServer, error).matches(INVALID_CONFIGURATION_ERROR);
    }

    @ParameterizedTest(name = "[aws-kms] construction accepts key ARN, alias ARN, raw key id, raw alias {0}")
    @MethodSource("targets")
    void constructionAcceptsEveryIdentifierForm(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        for (Example<String> kmsKeyId : KmsInputs.validKmsIdentifiers(KMS_KEY_ARN)) {
            assertUsableKeyring(mpl, kmsKeyId.value(), List.of());
        }
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials without a data key: GenerateDataKey
    // -----------------------------------------------------------------------

    /** FakeKms replies with a different key than the keyring's own, and the EDK must record the key from the reply. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt builds the data key and EDK from GenerateDataKey {0}")
    @MethodSource("targets")
    void onEncryptBuildsDataKeyAndEdkFromGenerateDataKey(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        byte[] ciphertext = bytes(64, 2);

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(OTHER_KEY_ARN, plaintext, ciphertext));
            EncryptionMaterials encrypted = onEncrypt(mpl, fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN),
                initializeEncryption(mpl, ALGORITHM_SUITE));

            assertEquals(0, fakeKms.requests(FakeKms.ENCRYPT).size());
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key
            //# OnEncrypt MUST attempt to generate a new plaintext data key
            //# by calling [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).
            assertEquals(1, fakeKms.requests(FakeKms.GENERATE_DATA_KEY).size());
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - MUST set the plaintext data key on the [encryption materials](../structures.md#encryption-materials) as the response `Plaintext`.
            //
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - MUST output the modified [encryption materials](../structures.md#encryption-materials)
            assertArrayEquals(plaintext, bytes(encrypted.getPlaintextDataKey()));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
            assertEquals(1, encrypted.getEncryptedDataKeys().size());
            EncryptedDataKey edk = encrypted.getEncryptedDataKeys().get(0);
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - the [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
            assertArrayEquals(ciphertext, bytes(edk.getCiphertext()));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - the [key provider id](../structures.md#key-provider-id) MUST be "aws-kms".
            assertEquals(PROVIDER_ID, edk.getKeyProviderId());
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - the [key provider information](../structures.md#key-provider-information) MUST be the response `KeyId`.
            assertArrayEquals(OTHER_KEY_ARN.getBytes(StandardCharsets.UTF_8), bytes(edk.getKeyProviderInfo()));
        }
    }

    /** A configured key identifier form with an algorithm suite and its data key length. */
    record RequestCase(String kmsKeyId, AlgorithmSuiteId suite, int dataKeyLength) {
        @Override
        public String toString() {
            return kmsKeyId + " " + suite.getValue();
        }
    }

    static Stream<Arguments> requestCasesByTarget() {
        List<AlgorithmSuiteId> suites = List.of(
            AlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF,
            AlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_NO_KDF,
            AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        List<Integer> lengths = List.of(16, 24, 32);
        return KmsInputs.validKmsIdentifiers(KMS_KEY_ARN).stream().map(Example::value)
            .flatMap(id -> IntStream.range(0, suites.size())
                .mapToObj(i -> new RequestCase(id, suites.get(i), lengths.get(i))))
            .flatMap(c -> targets().stream().map(languageServer -> Arguments.of(c, languageServer)));
    }

    @ParameterizedTest(name = "[aws-kms] GenerateDataKey request for {0} {1}")
    @MethodSource("requestCasesByTarget")
    void generateDataKeyRequest(RequestCase requestCase, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(KMS_KEY_ARN,
                bytes(requestCase.dataKeyLength(), 1), bytes(64, 2)));
            String keyringId = createKeyring(mpl, requestCase.kmsKeyId(), fakeKmsClient(fakeKms), GRANT_TOKENS);
            onEncrypt(mpl, keyringId, initializeEncryption(mpl, requestCase.suite()));

            List<FakeKms.Request> requests = fakeKms.requests(FakeKms.GENERATE_DATA_KEY);
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
            //
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The keyring MUST call AWS KMS GenerateDataKeys with a request constructed as follows:
            assertEquals(1, requests.size());
            FakeKms.Request request = requests.get(0);
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `KeyId` MUST be the keyring's KMS key identifier.
            assertEquals(requestCase.kmsKeyId(), request.text("KeyId"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `NumberOfBytes` MUST be the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
            //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [encryption materials](../structures.md#encryption-materials).
            assertEquals(requestCase.dataKeyLength(), request.body().get("NumberOfBytes").asInt());
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
            //# included in the input [encryption materials](../structures.md#encryption-materials).
            assertEquals(ENCRYPTION_CONTEXT, request.stringMap("EncryptionContext"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            assertEquals(GRANT_TOKENS, request.stringList("GrantTokens"));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt fails when GenerateDataKey fails {0}")
    @MethodSource("targets")
    void onEncryptFailsWhenGenerateDataKeyFails(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
                .reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.error(KMS_ERROR_CODE));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the call to [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
            //# OnEncrypt MUST NOT modify the [encryption materials](../structures.md#encryption-materials) and MUST fail.
            // Accepts a successful GenerateDataKey call
            onEncrypt(mpl, keyringId, initializeEncryption(mpl, ALGORITHM_SUITE));
            // Rejects a failed GenerateDataKey call
            assertOnEncryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(initializeEncryption(mpl, ALGORITHM_SUITE))
                .withError(KMS_CALL_FAILED_ERROR);
        }
    }

    static Stream<Arguments> wrongPlaintextLengthsByTarget() {
        return Stream.of(DATA_KEY_LENGTH - 1, DATA_KEY_LENGTH + 1)
            .flatMap(length -> targets().stream().map(languageServer -> Arguments.of(length, languageServer)));
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects a {0}-byte GenerateDataKey plaintext {1}")
    @MethodSource("wrongPlaintextLengthsByTarget")
    void onEncryptRejectsGeneratedPlaintextOfWrongLength(int length, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
                .reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(length, 1), bytes(64, 2)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that the response `Plaintext` length matches
            //# the specification of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.
            // Accepts a GenerateDataKey plaintext of the suite's length
            onEncrypt(mpl, keyringId, initializeEncryption(mpl, ALGORITHM_SUITE));
            // Rejects a GenerateDataKey plaintext one byte short or long
            assertOnEncryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(initializeEncryption(mpl, ALGORITHM_SUITE))
                .withError(REJECTED_KMS_REPLY_ERROR);
        }
    }

    /** KeyIds for a KMS reply that are not any form of KMS identifier. */
    static Stream<Arguments> garbageReplyKeyIdsByTarget() {
        return Stream.of("foo/bar", "arn:aws:kms:" + REGION + ":" + ACCOUNT)
            .flatMap(keyId -> targets().stream().map(languageServer -> Arguments.of(keyId, languageServer)));
    }

    /** KeyIds for a KMS reply that are KMS identifiers, but not key ARNs. */
    static Stream<Arguments> nonArnReplyKeyIdsByTarget() {
        return Stream.of(KEY_ID, ALIAS_ARN)
            .flatMap(keyId -> targets().stream().map(languageServer -> Arguments.of(keyId, languageServer)));
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects GenerateDataKey reply KeyId {0} {1}")
    @MethodSource("garbageReplyKeyIdsByTarget")
    void onEncryptRejectsGarbageGenerateDataKeyKeyId(String keyId, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
                .reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(keyId, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            // Accepts a GenerateDataKey reply KeyId that is a key ARN
            onEncrypt(mpl, keyringId, initializeEncryption(mpl, ALGORITHM_SUITE));
            // Rejects a GenerateDataKey reply KeyId that is not a KMS identifier
            assertOnEncryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(initializeEncryption(mpl, ALGORITHM_SUITE))
                .withError(REJECTED_KMS_REPLY_ERROR);
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects GenerateDataKey reply KeyId {0} {1}")
    @MethodSource("nonArnReplyKeyIdsByTarget")
    void onEncryptRejectsNonArnGenerateDataKeyKeyId(String keyId, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
                .reply(FakeKms.GENERATE_DATA_KEY,
                    FakeKms.Reply.generateDataKey(keyId, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);
            EncryptionMaterials materials = initializeEncryption(mpl, ALGORITHM_SUITE);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            // Accepts a GenerateDataKey reply KeyId that is a key ARN
            onEncrypt(mpl, keyringId, initializeEncryption(mpl, ALGORITHM_SUITE));
            // Rejects a GenerateDataKey reply KeyId that is a raw key id or an alias ARN
            KnownBugGate.gateDeclared("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn", languageServer,
                () -> assertOnEncryptFails()
                    .languageServer(languageServer)
                    .keyringId(keyringId)
                    .materials(materials)
                    .withError(REJECTED_KMS_REPLY_ERROR));
        }
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials with a data key: Encrypt
    // -----------------------------------------------------------------------

    static Stream<Arguments> keyIdFormsByTarget() {
        return forEachLanguageServer(KmsInputs.validKmsIdentifiers(KMS_KEY_ARN).stream().map(Example::value).toList());
    }

    /** FakeKms replies with a different key than the keyring's own, and the EDK must record the key from the reply. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt encrypts the existing data key with {0} {1}")
    @MethodSource("keyIdFormsByTarget")
    void onEncryptEncryptsExistingDataKey(String kmsKeyId, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        byte[] dataKey = bytes(DATA_KEY_LENGTH, 3);
        byte[] ciphertext = bytes(64, 4);

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(OTHER_KEY_ARN, ciphertext));
            String keyringId = createKeyring(mpl, kmsKeyId, fakeKmsClient(fakeKms), GRANT_TOKENS);
            EncryptionMaterials encrypted = onEncrypt(mpl, keyringId, materialsWithDataKey(mpl, dataKey));

            assertEquals(0, fakeKms.requests(FakeKms.GENERATE_DATA_KEY).size());
            List<FakeKms.Request> requests = fakeKms.requests(FakeKms.ENCRYPT);
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the input [encryption materials](../structures.md#encryption-materials) do contain a plaintext data key,
            //# OnEncrypt MUST attempt to encrypt the plaintext data key using the configured AWS KMS key identifier.
            //
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
            //
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The keyring MUST AWS KMS Encrypt call with a request constructed as follows:
            assertEquals(1, requests.size());
            FakeKms.Request request = requests.get(0);
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            assertEquals(kmsKeyId, request.text("KeyId"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).
            assertArrayEquals(dataKey, request.blob("Plaintext"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
            //# included in the input [encryption materials](../structures.md#encryption-materials).
            assertEquals(ENCRYPTION_CONTEXT, request.stringMap("EncryptionContext"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            assertEquals(GRANT_TOKENS, request.stringList("GrantTokens"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If all Encrypt calls succeed, OnEncrypt MUST output the modified [encryption materials](../structures.md#encryption-materials).
            assertArrayEquals(dataKey, bytes(encrypted.getPlaintextDataKey()));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If verified, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
            assertEquals(1, encrypted.getEncryptedDataKeys().size());
            EncryptedDataKey edk = encrypted.getEncryptedDataKeys().get(0);
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - The [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
            assertArrayEquals(ciphertext, bytes(edk.getCiphertext()));
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - The [key provider id](../structures.md#key-provider-id) MUST be "aws-kms".
            assertEquals(PROVIDER_ID, edk.getKeyProviderId());
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - The [key provider information](../structures.md#key-provider-information) MUST be the response `KeyId`.
            assertArrayEquals(OTHER_KEY_ARN.getBytes(StandardCharsets.UTF_8), bytes(edk.getKeyProviderInfo()));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt fails when Encrypt fails {0}")
    @MethodSource("targets")
    void onEncryptFailsWhenEncryptFails(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(KMS_KEY_ARN, bytes(64, 4)))
                .reply(FakeKms.ENCRYPT, FakeKms.Reply.error(KMS_ERROR_CODE));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
            // Accepts a successful Encrypt call
            onEncrypt(mpl, keyringId, materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
            // Rejects a failed Encrypt call
            assertOnEncryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)))
                .withError(KMS_CALL_FAILED_ERROR);
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects Encrypt reply KeyId {0} {1}")
    @MethodSource("garbageReplyKeyIdsByTarget")
    void onEncryptRejectsGarbageEncryptKeyId(String keyId, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(KMS_KEY_ARN, bytes(64, 4)))
                .reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(keyId, bytes(64, 4)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            // Accepts an Encrypt reply KeyId that is a key ARN
            onEncrypt(mpl, keyringId, materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
            // Rejects an Encrypt reply KeyId that is not a KMS identifier
            assertOnEncryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)))
                .withError(REJECTED_KMS_REPLY_ERROR);
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects Encrypt reply KeyId {0} {1}")
    @MethodSource("nonArnReplyKeyIdsByTarget")
    void onEncryptRejectsNonArnEncryptKeyId(String keyId, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(KMS_KEY_ARN, bytes(64, 4)))
                .reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(keyId, bytes(64, 4)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);
            EncryptionMaterials materials = materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3));

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            // Accepts an Encrypt reply KeyId that is a key ARN
            onEncrypt(mpl, keyringId, materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
            // Rejects an Encrypt reply KeyId that is a raw key id or an alias ARN
            KnownBugGate.gateDeclared("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn", languageServer,
                () -> assertOnEncryptFails()
                    .languageServer(languageServer)
                    .keyringId(keyringId)
                    .materials(materials)
                    .withError(REJECTED_KMS_REPLY_ERROR));
        }
    }

    // -----------------------------------------------------------------------
    // The KMS client that the keyring was given, with real KMS
    //
    // A us-east-2 KMS client cannot use a us-west-2 key.
    // Each test makes the same call twice.
    // Through a us-west-2 client the call works, which shows that the server's AWS credentials work.
    // Through a us-east-2 client it fails, which happens only if the keyring uses the client it was given.
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[aws-kms] GenerateDataKey goes through the configured client {0}")
    @MethodSource("targets")
    void generateDataKeyUsesConfiguredClient(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        String usWest2Keyring = realKmsKeyring(mpl);
        String usEast2Keyring = createKeyring(mpl, KMS_KEY_ARN, realKmsClient(OTHER_REGION), List.of());

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
        // Accepts a call through the us-west-2 client
        onEncrypt(mpl, usWest2Keyring, initializeEncryption(mpl, ALGORITHM_SUITE));
        // Rejects a call through the us-east-2 client
        assertOnEncryptFails()
            .languageServer(languageServer)
            .keyringId(usEast2Keyring)
            .materials(initializeEncryption(mpl, ALGORITHM_SUITE))
            .withError(WRONG_REGION_KMS_ERROR);
    }

    @ParameterizedTest(name = "[aws-kms] Encrypt goes through the configured client {0}")
    @MethodSource("targets")
    void encryptUsesConfiguredClient(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        String usWest2Keyring = realKmsKeyring(mpl);
        String usEast2Keyring = createKeyring(mpl, KMS_KEY_ARN, realKmsClient(OTHER_REGION), List.of());

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
        // Accepts a call through the us-west-2 client
        onEncrypt(mpl, usWest2Keyring, materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
        // Rejects a call through the us-east-2 client
        assertOnEncryptFails()
            .languageServer(languageServer)
            .keyringId(usEast2Keyring)
            .materials(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)))
            .withError(WRONG_REGION_KMS_ERROR);
    }

    @ParameterizedTest(name = "[aws-kms] Decrypt goes through the configured client {0}")
    @MethodSource("targets")
    void decryptUsesConfiguredClient(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        String usWest2Keyring = realKmsKeyring(mpl);
        String usEast2Keyring = createKeyring(mpl, KMS_KEY_ARN, realKmsClient(OTHER_REGION), List.of());
        List<EncryptedDataKey> edks =
            onEncrypt(mpl, usWest2Keyring, initializeEncryption(mpl, ALGORITHM_SUITE)).getEncryptedDataKeys();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
        //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        // Accepts a call through the us-west-2 client
        onDecrypt(mpl, usWest2Keyring, edks);
        // Rejects a call through the us-east-2 client
        assertOnDecryptFails()
            .languageServer(languageServer)
            .keyringId(usEast2Keyring)
            .materials(initializeDecryption(mpl))
            .encryptedDataKeys(edks)
            .withError(WRONG_REGION_KMS_ERROR);
    }

    /** One language's MPL encrypts and another language's MPL decrypts, both with real KMS. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt/OnDecrypt with real KMS {0}")
    @MethodSource("pairs")
    void roundTripWithRealKms(TargetPair pair) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), pair);
        MPLTestServerClient encryptingMpl = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient decryptingMpl = MplTestServerClients.forEndpoint(pair.decryptEndpoint());

        EncryptionMaterials encrypted = onEncrypt(encryptingMpl, realKmsKeyring(encryptingMpl), initializeEncryption(encryptingMpl, ALGORITHM_SUITE));
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        DecryptionMaterials decrypted = onDecrypt(decryptingMpl, realKmsKeyring(decryptingMpl), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    // -----------------------------------------------------------------------
    // OnDecrypt
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[aws-kms] OnDecrypt rejects materials with a data key {0}")
    @MethodSource("targets")
    void onDecryptRejectsMaterialsWithDataKey(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)))
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);
            DecryptionMaterials withKey = initializeDecryption(mpl).toBuilder()
                .plaintextDataKey(ByteBuffer.wrap(bytes(DATA_KEY_LENGTH, 5)))
                .build();

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key
            //# OnDecrypt MUST return an error.
            // Accepts materials without a data key
            onDecrypt(mpl, keyringId, List.of(edk(1)));
            // Rejects materials with a data key
            MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.onDecrypt(
                OnDecryptInput.builder()
                    .keyringId(keyringId)
                    .materials(withKey)
                    .encryptedDataKeys(List.of(edk(1)))
                    .build()));
            MplErrors.expectError(languageServer, error).matches(INVALID_MATERIALS_ERROR);
        }
    }

    static Stream<Arguments> otherProviderIdsByTarget() {
        return Stream.of("AWS-KMS", "raw-aes")
            .flatMap(id -> targets().stream().map(languageServer -> Arguments.of(id, languageServer)));
    }

    /**
     * An EDK for another provider or key, then an EDK for this keyring's key.
     * Only the second one may reach KMS.
     * FakeKms has one reply, so a keyring that sent both would see its second call fail.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt never sends an EDK with provider id {0} {1}")
    @MethodSource("otherProviderIdsByTarget")
    void onDecryptSkipsOtherProviderId(String providerId, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        EncryptedDataKey other = edk(1).toBuilder().keyProviderId(providerId).build();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - Its provider ID MUST exactly match the value “aws-kms”.
        assertOnlyMatchingEdkSentToKms(mpl, other);
    }

    static Stream<Arguments> otherProviderInfosByTarget() {
        String upperKeyId = arn("key/" + KEY_ID.toUpperCase(Locale.ROOT));
        return Stream.of(OTHER_KEY_ARN, upperKeyId)
            .flatMap(info -> targets().stream().map(languageServer -> Arguments.of(info, languageServer)));
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt never sends an EDK for key {0} {1}")
    @MethodSource("otherProviderInfosByTarget")
    void onDecryptSkipsOtherKeyArn(String providerInfo, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        EncryptedDataKey other = withProviderInfo(edk(1), providerInfo.getBytes(StandardCharsets.UTF_8));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST match the configured AWS KMS key identifier.
        assertOnlyMatchingEdkSentToKms(mpl, other);
    }

    /** Every EDK is for another provider or another key, so none may reach KMS. */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt with no EDK for its key fails {0}")
    @MethodSource("targets")
    void onDecryptWithNoMatchingEdkFails(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);
            List<EncryptedDataKey> others = List.of(
                edk(1).toBuilder().keyProviderId("raw-aes").build(),
                withProviderInfo(edk(2), OTHER_KEY_ARN.getBytes(StandardCharsets.UTF_8)));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
            //# then it MUST yield an error that includes all the collected errors.
            // Accepts an EDK for its key
            onDecrypt(mpl, keyringId, List.of(edk(1)));
            // Rejects EDKs that are all for another provider or another key
            assertOnDecryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(initializeDecryption(mpl))
                .encryptedDataKeys(others)
                .withError(NO_MATCHING_DATA_KEY_ERROR);
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
            // Only the EDK from the passing call reached KMS.
            assertDecryptCiphertexts(fakeKms, edk(1));
        }
    }

    /** Provider info that is not a key ARN, with a name for the test report. */
    record ProviderInfo(String name, byte[] bytes) {
        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<Arguments> nonArnProviderInfosByTarget() {
        return Stream.of(
                new ProviderInfo("non-UTF-8 bytes", new byte[] {(byte) 0xFF, (byte) 0xFE}),
                new ProviderInfo("not-an-arn", "not-an-arn".getBytes(StandardCharsets.UTF_8)),
                new ProviderInfo("raw key id", KEY_ID.getBytes(StandardCharsets.UTF_8)))
            .flatMap(info -> targets().stream().map(languageServer -> Arguments.of(info, languageServer)));
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails on provider info {0} {1}")
    @MethodSource("nonArnProviderInfosByTarget")
    void onDecryptFailsOnProviderInfoThatIsNotAnArn(ProviderInfo info, LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            // The second reply lets a keyring that skips the bad EDK decrypt EDK 2, so the test catches it.
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)))
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.
            // Accepts provider info that is a key ARN
            onDecrypt(mpl, keyringId, List.of(edk(1)));
            // Rejects provider info that is not an ARN
            assertOnDecryptFails()
                .languageServer(languageServer)
                .keyringId(keyringId)
                .materials(initializeDecryption(mpl))
                .encryptedDataKeys(List.of(withProviderInfo(edk(1), info.bytes()), edk(2)))
                .withError(INVALID_PROVIDER_INFO_ERROR);
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails on an alias ARN provider info {0}")
    @MethodSource("targets")
    void onDecryptFailsOnAliasArnProviderInfo(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            // The second reply lets a keyring that skips the alias EDK decrypt EDK 2, so the test catches it.
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)))
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);
            List<EncryptedDataKey> edks =
                List.of(withProviderInfo(edk(1), ALIAS_ARN.getBytes(StandardCharsets.UTF_8)), edk(2));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.
            // Accepts provider info that is a key ARN
            onDecrypt(mpl, keyringId, List.of(edk(1)));
            // Rejects provider info that is an alias ARN
            KnownBugGate.gateDeclared("aws-kms-keyring-skips-alias-arn-provider-info", languageServer,
                () -> assertOnDecryptFails()
                    .languageServer(languageServer)
                    .keyringId(keyringId)
                    .materials(initializeDecryption(mpl))
                    .encryptedDataKeys(edks)
                    .withError(INVALID_PROVIDER_INFO_ERROR));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt tries the next EDK after a failed Decrypt {0}")
    @MethodSource("targets")
    void onDecryptTriesNextEdkAfterFailedDecrypt(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.error(KMS_ERROR_CODE))
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(mpl, fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN),
                List.of(edk(1), edk(2)));

            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
            // The Decrypt call for EDK 1 fails, so FakeKms then gets one for EDK 2.
            assertDecryptCiphertexts(fakeKms, edk(1), edk(2));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt collects one error per EDK it tried {0}")
    @MethodSource("targets")
    void onDecryptCollectsOneErrorPerEdk(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            for (int i = 0; i < 3; i++) {
                fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.error(KMS_ERROR_CODE));
            }
            String keyringId = fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN);
            DecryptionMaterials materials = initializeDecryption(mpl);

            // Accepts an EDK that KMS decrypts
            onDecrypt(mpl, keyringId, List.of(edk(1)));
            // Rejects EDKs that KMS fails to decrypt
            MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.onDecrypt(
                OnDecryptInput.builder()
                    .keyringId(keyringId)
                    .materials(materials)
                    .encryptedDataKeys(List.of(edk(1), edk(2), edk(3)))
                    .build()));
            assertEquals(4, fakeKms.requests(FakeKms.DECRYPT).size());
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If this attempt results in an error, then these errors MUST be collected.
            //
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
            //# then it MUST yield an error that includes all the collected errors.
            assertEquals(3, error.getCollectedErrors().size(), "one collected error per EDK tried");
            MplErrors.expectError(languageServer, error).matches(KMS_CALL_FAILED_ERROR);
        }
    }

    @ParameterizedTest(name = "[aws-kms] Decrypt request {0}")
    @MethodSource("targets")
    void decryptRequest(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = createKeyring(mpl, KMS_KEY_ARN, fakeKmsClient(fakeKms), GRANT_TOKENS);
            onDecrypt(mpl, keyringId, List.of(edk(1)));

            List<FakeKms.Request> requests = fakeKms.requests(FakeKms.DECRYPT);
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), the keyring MUST call with a request constructed as follows:
            assertEquals(1, requests.size());
            FakeKms.Request request = requests.get(0);
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            assertEquals(KMS_KEY_ARN, request.text("KeyId"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
            assertArrayEquals(bytes(edk(1).getCiphertext()), request.blob("CiphertextBlob"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
            assertEquals(ENCRYPTION_CONTEXT, request.stringMap("EncryptionContext"));
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            assertEquals(GRANT_TOKENS, request.stringList("GrantTokens"));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips a Decrypt reply for another key {0}")
    @MethodSource("targets")
    void onDecryptSkipsReplyForAnotherKey(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The `KeyId` field in the response MUST equal the configured AWS KMS key identifier.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.
        assertBadReplySkipped(languageServer, FakeKms.Reply.decrypt(OTHER_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)),
            plaintext);
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips a Decrypt reply plaintext of the wrong length {0}")
    @MethodSource("targets")
    void onDecryptSkipsPlaintextOfWrongLength(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The length of the response’s `Plaintext` MUST equal the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
        //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [decryption materials](../structures.md#decryption-materials).
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.
        assertBadReplySkipped(languageServer, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH / 2, 1)),
            plaintext);
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt returns the first data key KMS decrypts {0}")
    @MethodSource("targets")
    void onDecryptReturnsFirstDecryptedDataKey(LanguageServerTarget languageServer) {
        FeatureGate.require(Set.of(AWS_KMS_FEATURE), languageServer);
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(mpl, fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN),
                List.of(edk(1), edk(2)));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - MUST set the plaintext data key on the [decryption materials](../structures.md#decryption-materials) as the response `Plaintext`.
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).
            // Both EDKs match, but FakeKms gets only the Decrypt call for EDK 1.
            assertDecryptCiphertexts(fakeKms, edk(1));
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static String arn(String resource) {
        return "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":" + resource;
    }

    /**
     * An aws-kms EDK for this keyring's key.
     * Each {@code seed} gives a different ciphertext, so the tests can tell EDKs apart.
     */
    private static EncryptedDataKey edk(int seed) {
        return EncryptedDataKey.builder()
            .keyProviderId(PROVIDER_ID)
            .keyProviderInfo(ByteBuffer.wrap(KMS_KEY_ARN.getBytes(StandardCharsets.UTF_8)))
            .ciphertext(ByteBuffer.wrap(bytes(64, seed)))
            .build();
    }

    private static EncryptedDataKey withProviderInfo(EncryptedDataKey edk, byte[] providerInfo) {
        return edk.toBuilder().keyProviderInfo(ByteBuffer.wrap(providerInfo)).build();
    }

    /** {@code other}, then an EDK for this keyring's key: OnDecrypt succeeds and sends only the second one to KMS. */
    private static void assertOnlyMatchingEdkSentToKms(MPLTestServerClient mpl, EncryptedDataKey other) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(mpl, fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN),
                List.of(other, edk(2)));
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(fakeKms, edk(2));
        }
    }

    /**
     * {@code bad} is a Decrypt reply for EDK 1.
     * With a good reply for EDK 2 after it, OnDecrypt returns EDK 2's data key.
     * With EDK 1 alone, OnDecrypt fails.
     */
    private static void assertBadReplySkipped(LanguageServerTarget languageServer, FakeKms.Reply bad, byte[] plaintext) {
        MPLTestServerClient mpl = MplTestServerClients.forEndpoint(languageServer.endpoint());
        // Accepts a good Decrypt reply for the EDK after the bad one
        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, bad)
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(mpl, fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN),
                List.of(edk(1), edk(2)));
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(fakeKms, edk(1), edk(2));
        }
        // Rejects a bad Decrypt reply for the only EDK
        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, bad);
            assertOnDecryptFails()
                .languageServer(languageServer)
                .keyringId(fakeKmsKeyring(mpl, fakeKms, KMS_KEY_ARN))
                .materials(initializeDecryption(mpl))
                .encryptedDataKeys(List.of(edk(1)))
                .withError(REJECTED_KMS_REPLY_ERROR);
        }
    }

    /** FakeKms got one Decrypt request for each EDK given, in that order. */
    private static void assertDecryptCiphertexts(FakeKms fakeKms, EncryptedDataKey... edks) {
        List<FakeKms.Request> requests = fakeKms.requests(FakeKms.DECRYPT);
        assertEquals(edks.length, requests.size(), "Decrypt calls");
        for (int i = 0; i < edks.length; i++) {
            assertArrayEquals(bytes(edks[i].getCiphertext()), requests.get(i).blob("CiphertextBlob"),
                "Decrypt call " + i + " ciphertext");
        }
    }

    /**
     * Create a keyring with FakeKms as its KMS client, and check that it works.
     * A keyring for KMS_KEY_ARN must encrypt a data key and decrypt it again.
     * A keyring for a raw key ID or an alias only runs OnEncrypt, because OnDecrypt needs a key ARN.
     */
    private static void assertUsableKeyring(MPLTestServerClient mpl, String kmsKeyId, List<String> grantTokens) {
        byte[] dataKey = bytes(DATA_KEY_LENGTH, 9);
        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(KMS_KEY_ARN, dataKey, bytes(64, 9)))
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, dataKey));
            String keyringId = createKeyring(mpl, kmsKeyId, fakeKmsClient(fakeKms), grantTokens);
            if (kmsKeyId.equals(KMS_KEY_ARN)) {
                assertKeyringRoundTrips(mpl, keyringId,
                    initializeEncryption(mpl, ALGORITHM_SUITE), initializeDecryption(mpl));
            } else {
                onEncrypt(mpl, keyringId, initializeEncryption(mpl, ALGORITHM_SUITE));
            }
        }
    }

    private static KmsClientConfig realKmsClient(String region) {
        return KmsClientConfig.builder().region(region).build();
    }

    private static KmsClientConfig fakeKmsClient(FakeKms fakeKms) {
        return KmsClientConfig.builder().region(REGION).endpoint(fakeKms.endpoint()).build();
    }

    private static String realKmsKeyring(MPLTestServerClient mpl) {
        return createKeyring(mpl, KMS_KEY_ARN, realKmsClient(REGION), List.of());
    }

    private static String fakeKmsKeyring(MPLTestServerClient mpl, FakeKms fakeKms, String kmsKeyId) {
        return createKeyring(mpl, kmsKeyId, fakeKmsClient(fakeKms), List.of());
    }

    private static String createKeyring(MPLTestServerClient mpl, String kmsKeyId, KmsClientConfig kmsClient,
            List<String> grantTokens) {
        return MplTestServerClients.withRetry(() -> mpl.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(kmsKeyId)
            .kmsClient(kmsClient)
            .grantTokens(grantTokens)
            .build())).getKeyringId();
    }

    private static EncryptionMaterials initializeEncryption(MPLTestServerClient mpl, AlgorithmSuiteId suite) {
        return KeyringTestHelpers.initializeEncryption(mpl, suite, ENCRYPTION_CONTEXT);
    }

    private static EncryptionMaterials materialsWithDataKey(MPLTestServerClient mpl, byte[] dataKey) {
        return initializeEncryption(mpl, ALGORITHM_SUITE).toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(dataKey))
            .build();
    }

    private static DecryptionMaterials initializeDecryption(MPLTestServerClient mpl) {
        return KeyringTestHelpers.initializeDecryption(mpl, ALGORITHM_SUITE, ENCRYPTION_CONTEXT);
    }

    /** OnDecrypt with new decryption materials, which must succeed. */
    private static DecryptionMaterials onDecrypt(
            MPLTestServerClient mpl, String keyringId, List<EncryptedDataKey> encryptedDataKeys) {
        return KeyringTestHelpers.onDecrypt(mpl, keyringId, initializeDecryption(mpl), encryptedDataKeys);
    }
}
