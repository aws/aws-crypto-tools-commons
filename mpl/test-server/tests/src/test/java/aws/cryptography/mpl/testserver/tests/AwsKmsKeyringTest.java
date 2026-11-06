package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CreateAwsKmsKeyringInput;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.InitializeDecryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.InitializeEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.KmsClientConfig;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.mpl.testserver.client.model.OnDecryptInput;
import aws.cryptography.mpl.testserver.client.model.OnEncryptInput;
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
 * The AWS KMS keyring (the strict, single-key keyring; not discovery or MRK),
 * driven directly through the keyring interface, per aws-kms-keyring.md.
 *
 * <p>Most tests point the keyring's KMS client at {@link FakeKms}, which
 * scripts each KMS reply and saves each request, so a test can hand the keyring
 * a wrong reply and check exactly what the keyring sent.
 * The construction tests make no KMS call.
 * The tests that name a region instead of FakeKms call real KMS: every server
 * needs AWS credentials with KMS GenerateDataKey, Encrypt and Decrypt on
 * KMS_KEY_ARN.
 */
public class AwsKmsKeyringTest {

    private static final String FEATURE = "aws-kms";

    // The KMS key in the CI-resources account 370957321024 that the
    // hierarchical keyring tests also use.
    // THIS IS A TESTING RESOURCE. DO NOT USE IT IN A PRODUCTION ENVIRONMENT.
    private static final String REGION = "us-west-2";
    private static final String ACCOUNT = "370957321024";
    private static final String KEY_ID = "9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String KMS_KEY_ARN = arn("key/" + KEY_ID);
    private static final String ALIAS_ARN = arn("alias/x");
    private static final String RAW_ALIAS = "alias/x";
    /** A well-formed key ARN for a key other than KMS_KEY_ARN. */
    private static final String OTHER_KEY_ARN = arn("key/00000000-0000-0000-0000-000000000000");
    private static final String OTHER_REGION = "us-east-2";

    private static final String PROVIDER_ID = "aws-kms";
    private static final List<String> GRANT_TOKENS = List.of("grant-token-a", "grant-token-b");

    /** Non-signing suites, so the materials carry no signing key. */
    private static final AlgorithmSuiteId SUITE = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
    private static final int DATA_KEY_LENGTH = 32;

    private static final Map<String, String> EC = Map.of("purpose", "aws-kms-keyring-test");

    /** A real-KMS error type for a failed call. */
    private static final String KMS_ERROR = "NotFoundException";

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
    void constructionWithoutKeyIdFails(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS key identifier
        assertThrows(MPLClientError.class, () -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsClient(realKms(REGION))
            .build()));
    }

    @ParameterizedTest(name = "[aws-kms] construction without a KMS client fails {0}")
    @MethodSource("targets")
    void constructionWithoutKmsClientFails(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS SDK client
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS SDK client MUST NOT be null.
        KnownBugGate.gateDeclared("aws-kms-keyring-accepts-missing-kms-client", target,
            () -> assertThrows(MPLClientError.class, () -> client.createAwsKmsKeyring(
                CreateAwsKmsKeyringInput.builder()
                    .kmsKeyId(KMS_KEY_ARN)
                    .build())));
    }

    static Stream<Arguments> grantTokenListsByTarget() {
        List<List<String>> lists = List.of(
            IntStream.range(0, 10).mapToObj(i -> String.valueOf((char) ('a' + i))).toList(),
            IntStream.range(0, 10).mapToObj(i -> String.valueOf((char) ('a' + i)).repeat(8192)).toList());
        return lists.stream().flatMap(tokens -> targets().stream()
            .map(target -> Arguments.of(tokens.size() + " tokens of length " + tokens.get(0).length(),
                tokens, target)));
    }

    @ParameterizedTest(name = "[aws-kms] construction accepts {0} {2}")
    @MethodSource("grantTokenListsByTarget")
    void constructionAcceptsGrantTokens(String name, List<String> grantTokens, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MAY provide a list of Grant Tokens
        assertNotNull(createKeyring(client, KMS_KEY_ARN, realKms(REGION), grantTokens));
    }

    /** Grant token limits that KMS sets: at most 10 tokens, each 1 to 8192 characters. */
    static Stream<Arguments> invalidGrantTokenListsByTarget() {
        List<List<String>> lists = List.of(
            IntStream.rangeClosed(1, 11).mapToObj(i -> "grant-token-" + i).toList(),
            List.of(""),
            List.of("a".repeat(8193)));
        return lists.stream().flatMap(tokens -> targets().stream()
            .map(target -> Arguments.of(tokens.size() + " tokens, first of length " + tokens.get(0).length(),
                tokens, target)));
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects {0} {2}")
    @MethodSource("invalidGrantTokenListsByTarget")
    void constructionRejectsInvalidGrantTokens(String name, List<String> grantTokens,
            LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        assertThrows(MPLClientError.class, () -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(REGION))
            .grantTokens(grantTokens)
            .build()));
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects an empty key id {0}")
    @MethodSource("targets")
    void constructionRejectsEmptyKeyId(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST NOT be null or empty.
        assertThrows(MPLClientError.class, () -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId("")
            .kmsClient(realKms(REGION))
            .build()));
    }

    /** A key identifier that aws-kms-key-arn.md does not call valid. */
    record MalformedKeyId(String name, String kmsKeyId) {
        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<Arguments> malformedKeyIdsByTarget() {
        List<MalformedKeyId> ids = List.of(
            new MalformedKeyId("non-ASCII character", arn("key/9d989aa2-2f9c-438c-a745-cc57d3ad012\u00e9")),
            // A raw alias that is valid apart from its length.
            new MalformedKeyId("2049 characters", "alias/" + "a".repeat(2049 - "alias/".length())),
            new MalformedKeyId("5-part ARN", "arn:aws:kms:" + REGION + ":" + ACCOUNT),
            new MalformedKeyId("7-part ARN", KMS_KEY_ARN + ":extra"),
            new MalformedKeyId("empty partition", "arn::kms:" + REGION + ":" + ACCOUNT + ":key/" + KEY_ID),
            new MalformedKeyId("empty region", "arn:aws:kms::" + ACCOUNT + ":key/" + KEY_ID),
            new MalformedKeyId("empty account", "arn:aws:kms:" + REGION + "::key/" + KEY_ID),
            new MalformedKeyId("service s3", "arn:aws:s3:" + REGION + ":" + ACCOUNT + ":key/" + KEY_ID),
            new MalformedKeyId("ARN resource foo/x", arn("foo/x")),
            new MalformedKeyId("ARN resource key/", arn("key/")),
            new MalformedKeyId("ARN resource key", arn("key")),
            new MalformedKeyId("raw key/<uuid>", "key/" + KEY_ID),
            new MalformedKeyId("raw foo/bar", "foo/bar"),
            new MalformedKeyId("raw alias/", "alias/"));
        return ids.stream().flatMap(id -> targets().stream().map(target -> Arguments.of(id, target)));
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects a key id with {0} {1}")
    @MethodSource("malformedKeyIdsByTarget")
    void constructionRejectsMalformedKeyId(MalformedKeyId malformed, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        assertThrows(MPLClientError.class, () -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(malformed.kmsKeyId())
            .kmsClient(realKms(REGION))
            .build()));
    }

    @ParameterizedTest(name = "[aws-kms] construction accepts key ARN, alias ARN, raw key id, raw alias {0}")
    @MethodSource("targets")
    void constructionAcceptsEveryIdentifierForm(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        for (String kmsKeyId : List.of(KMS_KEY_ARN, ALIAS_ARN, KEY_ID, RAW_ALIAS)) {
            assertNotNull(createKeyring(client, kmsKeyId, realKms(REGION), List.of()), kmsKeyId);
        }
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials without a data key: GenerateDataKey
    // -----------------------------------------------------------------------

    /** The reply names another key than the configured one, so the EDK must take it from the reply. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt builds the data key and EDK from GenerateDataKey {0}")
    @MethodSource("targets")
    void onEncryptBuildsDataKeyAndEdkFromGenerateDataKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        byte[] ciphertext = bytes(64, 2);

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(OTHER_KEY_ARN, plaintext, ciphertext));
            EncryptionMaterials encrypted = onEncrypt(client, fakeKmsKeyring(client, kms, KMS_KEY_ARN),
                initializeEncryption(client, SUITE));

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key
            //# OnEncrypt MUST attempt to generate a new plaintext data key
            //# by calling [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - MUST set the plaintext data key on the [encryption materials](../structures.md#encryption-materials) as the response `Plaintext`.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - the [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - the [key provider id](../structures.md#key-provider-id) MUST be "aws-kms".
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - the [key provider information](../structures.md#key-provider-information) MUST be the response `KeyId`.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - MUST output the modified [encryption materials](../structures.md#encryption-materials)
            assertEquals(1, kms.requests(FakeKms.GENERATE_DATA_KEY).size());
            assertEquals(0, kms.requests(FakeKms.ENCRYPT).size());
            assertArrayEquals(plaintext, bytes(encrypted.getPlaintextDataKey()));
            assertEquals(1, encrypted.getEncryptedDataKeys().size());
            EncryptedDataKey edk = encrypted.getEncryptedDataKeys().get(0);
            assertArrayEquals(ciphertext, bytes(edk.getCiphertext()));
            assertEquals(PROVIDER_ID, edk.getKeyProviderId());
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
        return Stream.of(KMS_KEY_ARN, KEY_ID, ALIAS_ARN, RAW_ALIAS)
            .flatMap(id -> IntStream.range(0, suites.size())
                .mapToObj(i -> new RequestCase(id, suites.get(i), lengths.get(i))))
            .flatMap(c -> targets().stream().map(target -> Arguments.of(c, target)));
    }

    @ParameterizedTest(name = "[aws-kms] GenerateDataKey request for {0} {1}")
    @MethodSource("requestCasesByTarget")
    void generateDataKeyRequest(RequestCase requestCase, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(KMS_KEY_ARN,
                bytes(requestCase.dataKeyLength(), 1), bytes(64, 2)));
            String keyringId = createKeyring(client, requestCase.kmsKeyId(), fakeKms(kms), GRANT_TOKENS);
            onEncrypt(client, keyringId, initializeEncryption(client, requestCase.suite()));

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The keyring MUST call AWS KMS GenerateDataKeys with a request constructed as follows:
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `KeyId` MUST be the keyring's KMS key identifier.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `NumberOfBytes` MUST be the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
            //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [encryption materials](../structures.md#encryption-materials).
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
            //# included in the input [encryption materials](../structures.md#encryption-materials).
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            List<FakeKms.Request> requests = kms.requests(FakeKms.GENERATE_DATA_KEY);
            assertEquals(1, requests.size());
            FakeKms.Request request = requests.get(0);
            assertEquals(requestCase.kmsKeyId(), request.text("KeyId"));
            assertEquals(requestCase.dataKeyLength(), request.body().get("NumberOfBytes").asInt());
            assertEquals(EC, request.stringMap("EncryptionContext"));
            assertEquals(GRANT_TOKENS, request.stringList("GrantTokens"));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt fails when GenerateDataKey fails {0}")
    @MethodSource("targets")
    void onEncryptFailsWhenGenerateDataKeyFails(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.error(KMS_ERROR));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the call to [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
            //# OnEncrypt MUST NOT modify the [encryption materials](../structures.md#encryption-materials) and MUST fail.
            assertOnEncryptFails(client, keyringId, initializeEncryption(client, SUITE));
        }
    }

    static Stream<Arguments> wrongPlaintextLengthsByTarget() {
        return Stream.of(DATA_KEY_LENGTH - 1, DATA_KEY_LENGTH + 1)
            .flatMap(length -> targets().stream().map(target -> Arguments.of(length, target)));
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects a {0}-byte GenerateDataKey plaintext {1}")
    @MethodSource("wrongPlaintextLengthsByTarget")
    void onEncryptRejectsGeneratedPlaintextOfWrongLength(int length, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(length, 1), bytes(64, 2)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that the response `Plaintext` length matches
            //# the specification of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.
            assertOnEncryptFails(client, keyringId, initializeEncryption(client, SUITE));
        }
    }

    /** Reply key ids that are not a KMS identifier of any form. */
    static Stream<Arguments> garbageReplyKeyIdsByTarget() {
        return Stream.of("foo/bar", "arn:aws:kms:" + REGION + ":" + ACCOUNT)
            .flatMap(keyId -> targets().stream().map(target -> Arguments.of(keyId, target)));
    }

    /** Reply key ids that are KMS identifiers, but not key ARNs. */
    static Stream<Arguments> nonArnReplyKeyIdsByTarget() {
        return Stream.of(KEY_ID, ALIAS_ARN)
            .flatMap(keyId -> targets().stream().map(target -> Arguments.of(keyId, target)));
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects GenerateDataKey reply KeyId {0} {1}")
    @MethodSource("garbageReplyKeyIdsByTarget")
    void onEncryptRejectsGarbageGenerateDataKeyKeyId(String keyId, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(keyId, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            assertOnEncryptFails(client, keyringId, initializeEncryption(client, SUITE));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects GenerateDataKey reply KeyId {0} {1}")
    @MethodSource("nonArnReplyKeyIdsByTarget")
    void onEncryptRejectsNonArnGenerateDataKeyKeyId(String keyId, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(keyId, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);
            EncryptionMaterials materials = initializeEncryption(client, SUITE);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            KnownBugGate.gateDeclared("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn", target,
                () -> assertOnEncryptFails(client, keyringId, materials));
        }
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials with a data key: Encrypt
    // -----------------------------------------------------------------------

    static Stream<Arguments> keyIdFormsByTarget() {
        return Stream.of(KMS_KEY_ARN, KEY_ID, ALIAS_ARN, RAW_ALIAS)
            .flatMap(keyId -> targets().stream().map(target -> Arguments.of(keyId, target)));
    }

    /** The reply names another key than the configured one, so the EDK must take it from the reply. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt encrypts the existing data key with {0} {1}")
    @MethodSource("keyIdFormsByTarget")
    void onEncryptEncryptsExistingDataKey(String kmsKeyId, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        byte[] dataKey = bytes(DATA_KEY_LENGTH, 3);
        byte[] ciphertext = bytes(64, 4);

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(OTHER_KEY_ARN, ciphertext));
            String keyringId = createKeyring(client, kmsKeyId, fakeKms(kms), GRANT_TOKENS);
            EncryptionMaterials encrypted = onEncrypt(client, keyringId, withDataKey(client, dataKey));

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
            //# included in the input [encryption materials](../structures.md#encryption-materials).
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the input [encryption materials](../structures.md#encryption-materials) do contain a plaintext data key,
            //# OnEncrypt MUST attempt to encrypt the plaintext data key using the configured AWS KMS key identifier.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# The keyring MUST AWS KMS Encrypt call with a request constructed as follows:
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If verified, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - The [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - The [key provider id](../structures.md#key-provider-id) MUST be "aws-kms".
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# - The [key provider information](../structures.md#key-provider-information) MUST be the response `KeyId`.
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If all Encrypt calls succeed, OnEncrypt MUST output the modified [encryption materials](../structures.md#encryption-materials).
            assertEquals(0, kms.requests(FakeKms.GENERATE_DATA_KEY).size());
            List<FakeKms.Request> requests = kms.requests(FakeKms.ENCRYPT);
            assertEquals(1, requests.size());
            FakeKms.Request request = requests.get(0);
            assertEquals(kmsKeyId, request.text("KeyId"));
            assertArrayEquals(dataKey, request.blob("Plaintext"));
            assertEquals(EC, request.stringMap("EncryptionContext"));
            assertEquals(GRANT_TOKENS, request.stringList("GrantTokens"));
            assertArrayEquals(dataKey, bytes(encrypted.getPlaintextDataKey()));
            assertEquals(1, encrypted.getEncryptedDataKeys().size());
            EncryptedDataKey edk = encrypted.getEncryptedDataKeys().get(0);
            assertArrayEquals(ciphertext, bytes(edk.getCiphertext()));
            assertEquals(PROVIDER_ID, edk.getKeyProviderId());
            assertArrayEquals(OTHER_KEY_ARN.getBytes(StandardCharsets.UTF_8), bytes(edk.getKeyProviderInfo()));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt fails when Encrypt fails {0}")
    @MethodSource("targets")
    void onEncryptFailsWhenEncryptFails(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.ENCRYPT, FakeKms.Reply.error(KMS_ERROR));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
            assertOnEncryptFails(client, keyringId, withDataKey(client, bytes(DATA_KEY_LENGTH, 3)));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects Encrypt reply KeyId {0} {1}")
    @MethodSource("garbageReplyKeyIdsByTarget")
    void onEncryptRejectsGarbageEncryptKeyId(String keyId, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(keyId, bytes(64, 4)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            assertOnEncryptFails(client, keyringId, withDataKey(client, bytes(DATA_KEY_LENGTH, 3)));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnEncrypt rejects Encrypt reply KeyId {0} {1}")
    @MethodSource("nonArnReplyKeyIdsByTarget")
    void onEncryptRejectsNonArnEncryptKeyId(String keyId, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(keyId, bytes(64, 4)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);
            EncryptionMaterials materials = withDataKey(client, bytes(DATA_KEY_LENGTH, 3));

            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //= type=test
            //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
            KnownBugGate.gateDeclared("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn", target,
                () -> assertOnEncryptFails(client, keyringId, materials));
        }
    }

    // -----------------------------------------------------------------------
    // The configured KMS client, with real KMS
    //
    // A us-east-2 client cannot use the us-west-2 key. Each call fails only if
    // the keyring sends it through the client it was given.
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[aws-kms] GenerateDataKey goes through the configured client {0}")
    @MethodSource("targets")
    void generateDataKeyUsesConfiguredClient(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String keyringId = createKeyring(client, KMS_KEY_ARN, realKms(OTHER_REGION), List.of());

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
        assertOnEncryptFails(client, keyringId, initializeEncryption(client, SUITE));
    }

    @ParameterizedTest(name = "[aws-kms] Encrypt goes through the configured client {0}")
    @MethodSource("targets")
    void encryptUsesConfiguredClient(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String keyringId = createKeyring(client, KMS_KEY_ARN, realKms(OTHER_REGION), List.of());

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
        assertOnEncryptFails(client, keyringId, withDataKey(client, bytes(DATA_KEY_LENGTH, 3)));
    }

    @ParameterizedTest(name = "[aws-kms] Decrypt goes through the configured client {0}")
    @MethodSource("targets")
    void decryptUsesConfiguredClient(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptionMaterials encrypted = onEncrypt(client, realKeyring(client), initializeEncryption(client, SUITE));
        String keyringId = createKeyring(client, KMS_KEY_ARN, realKms(OTHER_REGION), List.of());

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
        //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        assertOnDecryptFails(client, keyringId, encrypted.getEncryptedDataKeys());
    }

    /** OnEncrypt on one server and OnDecrypt on another, both against real KMS. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt/OnDecrypt with real KMS {0}")
    @MethodSource("pairs")
    void roundTripWithRealKms(TargetPair pair) {
        FeatureGate.require(Set.of(FEATURE), pair);
        MPLTestServerClient enc = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());

        EncryptionMaterials encrypted = onEncrypt(enc, realKeyring(enc), initializeEncryption(enc, SUITE));
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        DecryptionMaterials decrypted = onDecrypt(dec, realKeyring(dec), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    // -----------------------------------------------------------------------
    // OnDecrypt
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[aws-kms] OnDecrypt rejects materials with a data key {0}")
    @MethodSource("targets")
    void onDecryptRejectsMaterialsWithDataKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);
            DecryptionMaterials withKey = initializeDecryption(client).toBuilder()
                .plaintextDataKey(ByteBuffer.wrap(bytes(DATA_KEY_LENGTH, 5)))
                .build();

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key
            //# OnDecrypt MUST return an error.
            assertThrows(MPLClientError.class, () -> client.onDecrypt(OnDecryptInput.builder()
                .keyringId(keyringId)
                .materials(withKey)
                .encryptedDataKeys(List.of(edk(1)))
                .build()));
        }
    }

    static Stream<Arguments> otherProviderIdsByTarget() {
        return Stream.of("AWS-KMS", "raw-aes")
            .flatMap(id -> targets().stream().map(target -> Arguments.of(id, target)));
    }

    /**
     * A non-matching EDK ahead of a matching one: only the matching one may
     * reach KMS. FakeKms has one reply, so a keyring that sent both would see
     * the second call fail.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt never sends an EDK with provider id {0} {1}")
    @MethodSource("otherProviderIdsByTarget")
    void onDecryptSkipsOtherProviderId(String providerId, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey other = edk(1).toBuilder().keyProviderId(providerId).build();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - Its provider ID MUST exactly match the value “aws-kms”.
        assertOnlyMatchingEdkSentToKms(client, other);
    }

    static Stream<Arguments> otherProviderInfosByTarget() {
        String upperKeyId = arn("key/" + KEY_ID.toUpperCase(Locale.ROOT));
        return Stream.of(OTHER_KEY_ARN, upperKeyId)
            .flatMap(info -> targets().stream().map(target -> Arguments.of(info, target)));
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt never sends an EDK for key {0} {1}")
    @MethodSource("otherProviderInfosByTarget")
    void onDecryptSkipsOtherKeyArn(String providerInfo, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey other = withProviderInfo(edk(1), providerInfo.getBytes(StandardCharsets.UTF_8));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST match the configured AWS KMS key identifier.
        assertOnlyMatchingEdkSentToKms(client, other);
    }

    /** An aws-kms EDK whose provider info is not a key ARN, by name. */
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
            .flatMap(info -> targets().stream().map(target -> Arguments.of(info, target)));
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails on provider info {0} {1}")
    @MethodSource("nonArnProviderInfosByTarget")
    void onDecryptFailsOnProviderInfoThatIsNotAnArn(ProviderInfo info, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.
            assertOnDecryptFails(client, keyringId, List.of(withProviderInfo(edk(1), info.bytes()), edk(2)));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails on an alias ARN provider info {0}")
    @MethodSource("targets")
    void onDecryptFailsOnAliasArnProviderInfo(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);
            List<EncryptedDataKey> edks =
                List.of(withProviderInfo(edk(1), ALIAS_ARN.getBytes(StandardCharsets.UTF_8)), edk(2));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.
            KnownBugGate.gateDeclared("aws-kms-keyring-skips-alias-arn-provider-info", target,
                () -> assertOnDecryptFails(client, keyringId, edks));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt tries the next EDK after a failed Decrypt {0}")
    @MethodSource("targets")
    void onDecryptTriesNextEdkAfterFailedDecrypt(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.error(KMS_ERROR))
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(client, fakeKmsKeyring(client, kms, KMS_KEY_ARN),
                List.of(edk(1), edk(2)));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(kms, edk(1), edk(2));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt collects one error per EDK it tried {0}")
    @MethodSource("targets")
    void onDecryptCollectsOneErrorPerEdk(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            for (int i = 0; i < 3; i++) {
                kms.reply(FakeKms.DECRYPT, FakeKms.Reply.error(KMS_ERROR));
            }
            String keyringId = fakeKmsKeyring(client, kms, KMS_KEY_ARN);
            DecryptionMaterials materials = initializeDecryption(client);

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If this attempt results in an error, then these errors MUST be collected.
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
            //# then it MUST yield an error that includes all the collected errors.
            MPLClientError error = assertThrows(MPLClientError.class, () -> client.onDecrypt(
                OnDecryptInput.builder()
                    .keyringId(keyringId)
                    .materials(materials)
                    .encryptedDataKeys(List.of(edk(1), edk(2), edk(3)))
                    .build()));
            assertEquals(3, kms.requests(FakeKms.DECRYPT).size());
            assertNotNull(error.getCollectedErrors(), "the error carries the collected errors");
            assertEquals(3, error.getCollectedErrors().size(), "one collected error per EDK tried");
        }
    }

    @ParameterizedTest(name = "[aws-kms] Decrypt request {0}")
    @MethodSource("targets")
    void decryptRequest(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
            String keyringId = createKeyring(client, KMS_KEY_ARN, fakeKms(kms), GRANT_TOKENS);
            onDecrypt(client, keyringId, List.of(edk(1)));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), the keyring MUST call with a request constructed as follows:
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            List<FakeKms.Request> requests = kms.requests(FakeKms.DECRYPT);
            assertEquals(1, requests.size());
            FakeKms.Request request = requests.get(0);
            assertEquals(KMS_KEY_ARN, request.text("KeyId"));
            assertArrayEquals(bytes(edk(1).getCiphertext()), request.blob("CiphertextBlob"));
            assertEquals(EC, request.stringMap("EncryptionContext"));
            assertEquals(GRANT_TOKENS, request.stringList("GrantTokens"));
        }
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips a Decrypt reply for another key {0}")
    @MethodSource("targets")
    void onDecryptSkipsReplyForAnotherKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The `KeyId` field in the response MUST equal the configured AWS KMS key identifier.
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.
        assertBadReplySkipped(target, FakeKms.Reply.decrypt(OTHER_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)),
            plaintext);
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips a Decrypt reply plaintext of the wrong length {0}")
    @MethodSource("targets")
    void onDecryptSkipsPlaintextOfWrongLength(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The length of the response’s `Plaintext` MUST equal the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
        //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [decryption materials](../structures.md#decryption-materials).
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.
        assertBadReplySkipped(target, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH / 2, 1)),
            plaintext);
    }

    @ParameterizedTest(name = "[aws-kms] OnDecrypt returns the first data key KMS decrypts {0}")
    @MethodSource("targets")
    void onDecryptReturnsFirstDecryptedDataKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(client, fakeKmsKeyring(client, kms, KMS_KEY_ARN),
                List.of(edk(1), edk(2)));

            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - MUST set the plaintext data key on the [decryption materials](../structures.md#decryption-materials) as the response `Plaintext`.
            //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
            //= type=test
            //# - MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(kms, edk(1));
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static String arn(String resource) {
        return "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":" + resource;
    }

    /** A matching aws-kms EDK whose ciphertext {@code seed} tells apart from the others. */
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

    /** {@code other} then a matching EDK: OnDecrypt succeeds and sends only the matching one to KMS. */
    private static void assertOnlyMatchingEdkSentToKms(MPLTestServerClient client, EncryptedDataKey other) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(client, fakeKmsKeyring(client, kms, KMS_KEY_ARN),
                List.of(other, edk(2)));
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(kms, edk(2));
        }
    }

    /**
     * A bad Decrypt reply for the first EDK: alone, OnDecrypt fails; followed by
     * a second EDK whose reply is good, OnDecrypt returns the second data key.
     */
    private static void assertBadReplySkipped(LanguageServerTarget target, FakeKms.Reply bad, byte[] plaintext) {
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, bad);
            assertOnDecryptFails(client, fakeKmsKeyring(client, kms, KMS_KEY_ARN), List.of(edk(1)));
        }
        try (FakeKms kms = new FakeKms()) {
            kms.reply(FakeKms.DECRYPT, bad)
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            DecryptionMaterials decrypted = onDecrypt(client, fakeKmsKeyring(client, kms, KMS_KEY_ARN),
                List.of(edk(1), edk(2)));
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(kms, edk(1), edk(2));
        }
    }

    /** FakeKms received one Decrypt per EDK given, in that order. */
    private static void assertDecryptCiphertexts(FakeKms kms, EncryptedDataKey... edks) {
        List<FakeKms.Request> requests = kms.requests(FakeKms.DECRYPT);
        assertEquals(edks.length, requests.size(), "Decrypt calls");
        for (int i = 0; i < edks.length; i++) {
            assertArrayEquals(bytes(edks[i].getCiphertext()), requests.get(i).blob("CiphertextBlob"),
                "Decrypt call " + i + " ciphertext");
        }
    }

    private static void assertOnEncryptFails(MPLTestServerClient client, String keyringId,
            EncryptionMaterials materials) {
        assertThrows(MPLClientError.class, () -> client.onEncrypt(OnEncryptInput.builder()
            .keyringId(keyringId)
            .materials(materials)
            .build()));
    }

    private static void assertOnDecryptFails(MPLTestServerClient client, String keyringId,
            List<EncryptedDataKey> edks) {
        DecryptionMaterials materials = initializeDecryption(client);
        assertThrows(MPLClientError.class, () -> client.onDecrypt(OnDecryptInput.builder()
            .keyringId(keyringId)
            .materials(materials)
            .encryptedDataKeys(edks)
            .build()));
    }

    private static KmsClientConfig realKms(String region) {
        return KmsClientConfig.builder().region(region).build();
    }

    private static KmsClientConfig fakeKms(FakeKms kms) {
        return KmsClientConfig.builder().region(REGION).endpoint(kms.endpoint()).build();
    }

    private static String realKeyring(MPLTestServerClient client) {
        return createKeyring(client, KMS_KEY_ARN, realKms(REGION), List.of());
    }

    private static String fakeKmsKeyring(MPLTestServerClient client, FakeKms kms, String kmsKeyId) {
        return createKeyring(client, kmsKeyId, fakeKms(kms), List.of());
    }

    private static String createKeyring(MPLTestServerClient client, String kmsKeyId, KmsClientConfig kmsClient,
            List<String> grantTokens) {
        return MplTestServerClients.withRetry(() -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(kmsKeyId)
            .kmsClient(kmsClient)
            .grantTokens(grantTokens)
            .build())).getKeyringId();
    }

    private static EncryptionMaterials initializeEncryption(MPLTestServerClient client, AlgorithmSuiteId suite) {
        EncryptionMaterials materials = MplTestServerClients.withRetry(() ->
            client.initializeEncryptionMaterials(InitializeEncryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(EC)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "initialized materials carry no data key");
        return materials;
    }

    private static EncryptionMaterials withDataKey(MPLTestServerClient client, byte[] dataKey) {
        return initializeEncryption(client, SUITE).toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(dataKey))
            .build();
    }

    private static DecryptionMaterials initializeDecryption(MPLTestServerClient client) {
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            client.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(SUITE)
                .encryptionContext(EC)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "initialized materials carry no data key");
        return materials;
    }

    private static EncryptionMaterials onEncrypt(
        MPLTestServerClient client, String keyringId, EncryptionMaterials materials) {
        EncryptionMaterials out = MplTestServerClients.withRetry(() ->
            client.onEncrypt(OnEncryptInput.builder()
                .keyringId(keyringId)
                .materials(materials)
                .build())).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        assertEquals(materials.getAlgorithmSuiteId().getValue(), out.getAlgorithmSuiteId().getValue());
        return out;
    }

    private static DecryptionMaterials onDecrypt(
        MPLTestServerClient client, String keyringId, List<EncryptedDataKey> edks) {
        DecryptionMaterials materials = initializeDecryption(client);
        DecryptionMaterials out = MplTestServerClients.withRetry(() ->
            client.onDecrypt(OnDecryptInput.builder()
                .keyringId(keyringId)
                .materials(materials)
                .encryptedDataKeys(edks)
                .build())).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        return out;
    }

    /** {@code length} deterministic bytes; {@code seed} varies them. */
    private static byte[] bytes(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 7 + seed * 31 + 1);
        }
        return out;
    }

    /** Copy a ByteBuffer's remaining bytes without moving its position. */
    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }
}
