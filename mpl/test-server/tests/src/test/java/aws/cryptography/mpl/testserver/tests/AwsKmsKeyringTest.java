package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_CONFIGURATION_ERROR;
import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_MATERIALS_ERROR;
import static aws.cryptography.mpl.testserver.tests.MplErrors.NO_MATCHING_DATA_KEY_ERROR;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.KmsClientConfig;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.KmsInputs;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
 * The tests that use {@code realKms} call real KMS.
 * For those, every language's server needs AWS credentials that allow GenerateDataKey, Encrypt and Decrypt on KMS_KEY_ARN.
 */
public class AwsKmsKeyringTest implements KeyringTestDefaults {

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

    @Override
    public AlgorithmSuiteId algorithmSuite() {
        return ALGORITHM_SUITE;
    }

    @Override
    public Map<String, String> encryptionContext() {
        return ENCRYPTION_CONTEXT;
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction without a key id fails {0}")
    void constructionWithoutKeyIdFails(Mpl mpl, FakeKms fakeKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS key identifier
        // Accepts an AWS KMS key identifier
        fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create().assertEncryptsAndDecrypts();
        // Rejects a missing AWS KMS key identifier
        mpl.awsKmsKeyring().kmsClient(realKms(REGION)).createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction without a KMS client fails {0}")
    void constructionWithoutKmsClientFails(Mpl mpl, FakeKms fakeKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS SDK client
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS SDK client MUST NOT be null.
        // Accepts an AWS KMS client
        fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create().assertEncryptsAndDecrypts();
        // Rejects a missing AWS KMS client
        mpl.knownBug("aws-kms-keyring-accepts-missing-kms-client",
            () -> mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).createFailsWith(INVALID_CONFIGURATION_ERROR));
    }

    static List<Example<List<String>>> validGrantTokenLists() {
        return KmsInputs.validGrantTokenLists();
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction accepts {0} {1}", inputs = "validGrantTokenLists")
    void constructionAcceptsGrantTokens(Example<List<String>> grantTokens, Mpl mpl, FakeKms fakeKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MAY provide a list of Grant Tokens
        fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(fakeKms.client())
            .grantTokens(grantTokens.value())
            .create()
            .assertEncryptsAndDecrypts();
    }

    static List<Example<List<String>>> invalidGrantTokenLists() {
        return KmsInputs.invalidGrantTokenLists();
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction rejects {0} {1}", inputs = "invalidGrantTokenLists")
    void constructionRejectsInvalidGrantTokens(Example<List<String>> grantTokens, Mpl mpl, FakeKms fakeKms) {
        // Accepts valid grant tokens
        fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(fakeKms.client())
            .grantTokens(GRANT_TOKENS)
            .create()
            .assertEncryptsAndDecrypts();
        // Rejects invalid grant tokens
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(REGION))
            .grantTokens(grantTokens.value())
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction rejects an empty key id {0}")
    void constructionRejectsEmptyKeyId(Mpl mpl, FakeKms fakeKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST NOT be null or empty.
        // Accepts non-empty AWS KMS key identifier
        fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create().assertEncryptsAndDecrypts();
        // Rejects empty AWS KMS key identifier
        mpl.awsKmsKeyring().kmsKeyId("").kmsClient(realKms(REGION)).createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    static List<Example<String>> invalidKmsIdentifiers() {
        return KmsInputs.invalidKmsIdentifiers(KMS_KEY_ARN);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction rejects a key id with {0} {1}", inputs = "invalidKmsIdentifiers")
    void constructionRejectsMalformedKeyId(Example<String> malformed, Mpl mpl, FakeKms fakeKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        // Accepts valid AWS KMS key identifier
        fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create().assertEncryptsAndDecrypts();
        // Rejects malformed AWS KMS key identifier
        mpl.awsKmsKeyring()
            .kmsKeyId(malformed.value())
            .kmsClient(realKms(REGION))
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] construction accepts key ARN, alias ARN, raw key id, raw alias {0}")
    void constructionAcceptsEveryIdentifierForm(Mpl mpl) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        for (Example<String> kmsKeyId : KmsInputs.validKmsIdentifiers(KMS_KEY_ARN)) {
            // A new FakeKms for each keyring, so each one gets its own replies.
            try (FakeKms fakeKms = new FakeKms()) {
                fakeKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
                Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(kmsKeyId.value()).kmsClient(fakeKms.client()).create();
                // OnDecrypt needs a key ARN, so a keyring for a raw key ID or an alias only runs OnEncrypt.
                if (kmsKeyId.value().equals(KMS_KEY_ARN)) {
                    keyring.assertEncryptsAndDecrypts();
                } else {
                    keyring.onEncrypt(mpl.newEncryptionMaterials());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials without a data key: GenerateDataKey
    // -----------------------------------------------------------------------

    /** FakeKms replies with a different key than the keyring's own, and the EDK must record the key from the reply. */
    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt builds the data key and EDK from GenerateDataKey {0}")
    void onEncryptBuildsDataKeyAndEdkFromGenerateDataKey(Mpl mpl, FakeKms fakeKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        byte[] ciphertext = bytes(64, 2);

        fakeKms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(OTHER_KEY_ARN, plaintext, ciphertext));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());

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

    /** A configured key identifier form with an algorithm suite and its data key length. */
    record RequestCase(String kmsKeyId, AlgorithmSuiteId suite, int dataKeyLength) {
        @Override
        public String toString() {
            return kmsKeyId + " " + suite.getValue();
        }
    }

    /** Each key identifier form with each AES suite. */
    static List<RequestCase> requestCases() {
        List<RequestCase> cases = new ArrayList<>();
        for (Example<String> kmsKeyId : KmsInputs.validKmsIdentifiers(KMS_KEY_ARN)) {
            cases.add(new RequestCase(kmsKeyId.value(), AlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF, 16));
            cases.add(new RequestCase(kmsKeyId.value(), AlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_NO_KDF, 24));
            cases.add(new RequestCase(kmsKeyId.value(), AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, 32));
        }
        return cases;
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] GenerateDataKey request for {0} {1}", inputs = "requestCases")
    void generateDataKeyRequest(RequestCase requestCase, Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.generateDataKey(KMS_KEY_ARN,
            bytes(requestCase.dataKeyLength(), 1), bytes(64, 2)));
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(requestCase.kmsKeyId())
            .kmsClient(fakeKms.client())
            .grantTokens(GRANT_TOKENS)
            .create();
        keyring.onEncrypt(mpl.newEncryptionMaterials(requestCase.suite()));

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

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt fails when GenerateDataKey fails {0}")
    void onEncryptFailsWhenGenerateDataKeyFails(Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
            .reply(FakeKms.GENERATE_DATA_KEY, FakeKms.Reply.error(KMS_ERROR_CODE));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the call to [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
        //# OnEncrypt MUST NOT modify the [encryption materials](../structures.md#encryption-materials) and MUST fail.
        // Accepts a successful GenerateDataKey call
        keyring.onEncrypt(mpl.newEncryptionMaterials());
        // Rejects a failed GenerateDataKey call
        keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), KMS_CALL_FAILED_ERROR);
    }

    static List<Integer> wrongPlaintextLengths() {
        return List.of(DATA_KEY_LENGTH - 1, DATA_KEY_LENGTH + 1);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt rejects a {0}-byte GenerateDataKey plaintext {1}", inputs = "wrongPlaintextLengths")
    void onEncryptRejectsGeneratedPlaintextOfWrongLength(int length, Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
            .reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(length, 1), bytes(64, 2)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that the response `Plaintext` length matches
        //# the specification of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.
        // Accepts a GenerateDataKey plaintext of the suite's length
        keyring.onEncrypt(mpl.newEncryptionMaterials());
        // Rejects a GenerateDataKey plaintext one byte short or long
        keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), REJECTED_KMS_REPLY_ERROR);
    }

    /** KeyIds for a KMS reply that are not any form of KMS identifier. */
    static List<String> garbageReplyKeyIds() {
        return List.of("foo/bar", "arn:aws:kms:" + REGION + ":" + ACCOUNT);
    }

    /** KeyIds for a KMS reply that are KMS identifiers, but not key ARNs. */
    static List<String> nonArnReplyKeyIds() {
        return List.of(KEY_ID, ALIAS_ARN);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt rejects GenerateDataKey reply KeyId {0} {1}", inputs = "garbageReplyKeyIds")
    void onEncryptRejectsGarbageGenerateDataKeyKeyId(String keyId, Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
            .reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(keyId, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
        // Accepts a GenerateDataKey reply KeyId that is a key ARN
        keyring.onEncrypt(mpl.newEncryptionMaterials());
        // Rejects a GenerateDataKey reply KeyId that is not a KMS identifier
        keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), REJECTED_KMS_REPLY_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt rejects GenerateDataKey reply KeyId {0} {1}", inputs = "nonArnReplyKeyIds")
    void onEncryptRejectsNonArnGenerateDataKeyKeyId(String keyId, Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)))
            .reply(FakeKms.GENERATE_DATA_KEY,
                FakeKms.Reply.generateDataKey(keyId, bytes(DATA_KEY_LENGTH, 1), bytes(64, 2)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        EncryptionMaterials materials = mpl.newEncryptionMaterials();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
        // Accepts a GenerateDataKey reply KeyId that is a key ARN
        keyring.onEncrypt(mpl.newEncryptionMaterials());
        // Rejects a GenerateDataKey reply KeyId that is a raw key id or an alias ARN
        mpl.knownBug("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn",
            () -> keyring.onEncryptFailsWith(materials, REJECTED_KMS_REPLY_ERROR));
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials with a data key: Encrypt
    // -----------------------------------------------------------------------

    static List<String> kmsKeyIdForms() {
        return KmsInputs.validKmsIdentifiers(KMS_KEY_ARN).stream().map(kmsKeyId -> kmsKeyId.value()).toList();
    }

    /** FakeKms replies with a different key than the keyring's own, and the EDK must record the key from the reply. */
    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt encrypts the existing data key with {0} {1}", inputs = "kmsKeyIdForms")
    void onEncryptEncryptsExistingDataKey(String kmsKeyId, Mpl mpl, FakeKms fakeKms) {
        byte[] dataKey = bytes(DATA_KEY_LENGTH, 3);
        byte[] ciphertext = bytes(64, 4);

        fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(OTHER_KEY_ARN, ciphertext));
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(kmsKeyId)
            .kmsClient(fakeKms.client())
            .grantTokens(GRANT_TOKENS)
            .create();
        EncryptionMaterials encrypted = keyring.onEncrypt(materialsWithDataKey(mpl, dataKey));

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

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt fails when Encrypt fails {0}")
    void onEncryptFailsWhenEncryptFails(Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(KMS_KEY_ARN, bytes(64, 4)))
            .reply(FakeKms.ENCRYPT, FakeKms.Reply.error(KMS_ERROR_CODE));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
        // Accepts a successful Encrypt call
        keyring.onEncrypt(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
        // Rejects a failed Encrypt call
        keyring.onEncryptFailsWith(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)), KMS_CALL_FAILED_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt rejects Encrypt reply KeyId {0} {1}", inputs = "garbageReplyKeyIds")
    void onEncryptRejectsGarbageEncryptKeyId(String keyId, Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(KMS_KEY_ARN, bytes(64, 4)))
            .reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(keyId, bytes(64, 4)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
        // Accepts an Encrypt reply KeyId that is a key ARN
        keyring.onEncrypt(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
        // Rejects an Encrypt reply KeyId that is not a KMS identifier
        keyring.onEncryptFailsWith(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)), REJECTED_KMS_REPLY_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt rejects Encrypt reply KeyId {0} {1}", inputs = "nonArnReplyKeyIds")
    void onEncryptRejectsNonArnEncryptKeyId(String keyId, Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(KMS_KEY_ARN, bytes(64, 4)))
            .reply(FakeKms.ENCRYPT, FakeKms.Reply.encrypt(keyId, bytes(64, 4)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        EncryptionMaterials materials = materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3));

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
        // Accepts an Encrypt reply KeyId that is a key ARN
        keyring.onEncrypt(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
        // Rejects an Encrypt reply KeyId that is a raw key id or an alias ARN
        mpl.knownBug("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn",
            () -> keyring.onEncryptFailsWith(materials, REJECTED_KMS_REPLY_ERROR));
    }

    // -----------------------------------------------------------------------
    // The KMS client that the keyring was given, with real KMS
    //
    // A us-east-2 KMS client cannot use a us-west-2 key.
    // Each test makes the same call twice.
    // Through a us-west-2 client the call works, which shows that the server's AWS credentials work.
    // Through a us-east-2 client it fails, which happens only if the keyring uses the client it was given.
    // -----------------------------------------------------------------------

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] GenerateDataKey goes through the configured client {0}")
    void generateDataKeyUsesConfiguredClient(Mpl mpl) {
        Keyring usWest2Keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(REGION)).create();
        Keyring usEast2Keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(OTHER_REGION)).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
        // Accepts a call through the us-west-2 client
        usWest2Keyring.onEncrypt(mpl.newEncryptionMaterials());
        // Rejects a call through the us-east-2 client
        usEast2Keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), WRONG_REGION_KMS_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] Encrypt goes through the configured client {0}")
    void encryptUsesConfiguredClient(Mpl mpl) {
        Keyring usWest2Keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(REGION)).create();
        Keyring usEast2Keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(OTHER_REGION)).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
        // Accepts a call through the us-west-2 client
        usWest2Keyring.onEncrypt(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)));
        // Rejects a call through the us-east-2 client
        usEast2Keyring.onEncryptFailsWith(materialsWithDataKey(mpl, bytes(DATA_KEY_LENGTH, 3)), WRONG_REGION_KMS_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] Decrypt goes through the configured client {0}")
    void decryptUsesConfiguredClient(Mpl mpl) {
        Keyring usWest2Keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(REGION)).create();
        Keyring usEast2Keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(OTHER_REGION)).create();
        List<EncryptedDataKey> edks = usWest2Keyring.onEncrypt(mpl.newEncryptionMaterials()).getEncryptedDataKeys();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
        //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        // Accepts a call through the us-west-2 client
        usWest2Keyring.onDecrypt(mpl.newDecryptionMaterials(), edks);
        // Rejects a call through the us-east-2 client
        usEast2Keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), edks, WRONG_REGION_KMS_ERROR);
    }

    /** One language's MPL encrypts and another language's MPL decrypts, both with real KMS. */
    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnEncrypt/OnDecrypt with real KMS {0}", pairs = true)
    void roundTripWithRealKms(Mpl encryptingMpl, Mpl decryptingMpl) {
        Keyring encryptingKeyring =
            encryptingMpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(REGION)).create();
        EncryptionMaterials encrypted = encryptingKeyring.onEncrypt(encryptingMpl.newEncryptionMaterials());
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        Keyring decryptingKeyring =
            decryptingMpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(realKms(REGION)).create();
        DecryptionMaterials decrypted =
            decryptingKeyring.onDecrypt(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    // -----------------------------------------------------------------------
    // OnDecrypt
    // -----------------------------------------------------------------------

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt rejects materials with a data key {0}")
    void onDecryptRejectsMaterialsWithDataKey(Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)))
            .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        DecryptionMaterials withKey = mpl.newDecryptionMaterials().toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(bytes(DATA_KEY_LENGTH, 5)))
            .build();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key
        //# OnDecrypt MUST return an error.
        // Accepts materials without a data key
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));
        // Rejects materials with a data key
        keyring.onDecryptFailsWith(withKey, List.of(edk(1)), INVALID_MATERIALS_ERROR);
    }

    static List<String> otherProviderIds() {
        return List.of("AWS-KMS", "raw-aes");
    }

    /**
     * An EDK for another provider or key, then an EDK for this keyring's key.
     * Only the second one may reach KMS.
     * FakeKms has one reply, so a keyring that sent both would see its second call fail.
     */
    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt never sends an EDK with provider id {0} {1}", inputs = "otherProviderIds")
    void onDecryptSkipsOtherProviderId(String providerId, Mpl mpl, FakeKms fakeKms) {
        EncryptedDataKey other = edk(1).toBuilder().keyProviderId(providerId).build();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - Its provider ID MUST exactly match the value “aws-kms”.
        assertOnlyMatchingEdkSentToKms(mpl, fakeKms, other);
    }

    static List<String> otherProviderInfos() {
        String upperKeyId = arn("key/" + KEY_ID.toUpperCase(Locale.ROOT));
        return List.of(OTHER_KEY_ARN, upperKeyId);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt never sends an EDK for key {0} {1}", inputs = "otherProviderInfos")
    void onDecryptSkipsOtherKeyArn(String providerInfo, Mpl mpl, FakeKms fakeKms) {
        EncryptedDataKey other = withProviderInfo(edk(1), providerInfo.getBytes(StandardCharsets.UTF_8));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST match the configured AWS KMS key identifier.
        assertOnlyMatchingEdkSentToKms(mpl, fakeKms, other);
    }

    /** Every EDK is for another provider or another key, so none may reach KMS. */
    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt with no EDK for its key fails {0}")
    void onDecryptWithNoMatchingEdkFails(Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        List<EncryptedDataKey> others = List.of(
            edk(1).toBuilder().keyProviderId("raw-aes").build(),
            withProviderInfo(edk(2), OTHER_KEY_ARN.getBytes(StandardCharsets.UTF_8)));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
        //# then it MUST yield an error that includes all the collected errors.
        // Accepts an EDK for its key
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));
        // Rejects EDKs that are all for another provider or another key
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), others, NO_MATCHING_DATA_KEY_ERROR);
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        // Only the EDK from the passing call reached KMS.
        assertDecryptCiphertexts(fakeKms, edk(1));
    }

    /** Provider info that is not a key ARN, with a name for the test report. */
    record ProviderInfo(String name, byte[] bytes) {
        @Override
        public String toString() {
            return name;
        }
    }

    static List<ProviderInfo> nonArnProviderInfos() {
        return List.of(
            new ProviderInfo("non-UTF-8 bytes", new byte[] {(byte) 0xFF, (byte) 0xFE}),
            new ProviderInfo("not-an-arn", "not-an-arn".getBytes(StandardCharsets.UTF_8)),
            new ProviderInfo("raw key id", KEY_ID.getBytes(StandardCharsets.UTF_8)));
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt fails on provider info {0} {1}", inputs = "nonArnProviderInfos")
    void onDecryptFailsOnProviderInfoThatIsNotAnArn(ProviderInfo info, Mpl mpl, FakeKms fakeKms) {
        // The second reply lets a keyring that skips the bad EDK decrypt EDK 2, so the test catches it.
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)))
            .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.
        // Accepts provider info that is a key ARN
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));
        // Rejects provider info that is not an ARN
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(),
            List.of(withProviderInfo(edk(1), info.bytes()), edk(2)), INVALID_PROVIDER_INFO_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt fails on an alias ARN provider info {0}")
    void onDecryptFailsOnAliasArnProviderInfo(Mpl mpl, FakeKms fakeKms) {
        // The second reply lets a keyring that skips the alias EDK decrypt EDK 2, so the test catches it.
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)))
            .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        List<EncryptedDataKey> edks =
            List.of(withProviderInfo(edk(1), ALIAS_ARN.getBytes(StandardCharsets.UTF_8)), edk(2));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.
        // Accepts provider info that is a key ARN
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));
        // Rejects provider info that is an alias ARN
        mpl.knownBug("aws-kms-keyring-skips-alias-arn-provider-info",
            () -> keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), edks, INVALID_PROVIDER_INFO_ERROR));
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt tries the next EDK after a failed Decrypt {0}")
    void onDecryptTriesNextEdkAfterFailedDecrypt(Mpl mpl, FakeKms fakeKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.error(KMS_ERROR_CODE))
            .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        DecryptionMaterials decrypted = keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));

        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
        // The Decrypt call for EDK 1 fails, so FakeKms then gets one for EDK 2.
        assertDecryptCiphertexts(fakeKms, edk(1), edk(2));
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt collects one error per EDK it tried {0}")
    void onDecryptCollectsOneErrorPerEdk(Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
        for (int i = 0; i < 3; i++) {
            fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.error(KMS_ERROR_CODE));
        }
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        DecryptionMaterials materials = mpl.newDecryptionMaterials();

        // Accepts an EDK that KMS decrypts
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));
        // Rejects EDKs that KMS fails to decrypt
        MPLClientError error =
            keyring.onDecryptFailsWith(materials, List.of(edk(1), edk(2), edk(3)), KMS_CALL_FAILED_ERROR);
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
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] Decrypt request {0}")
    void decryptRequest(Mpl mpl, FakeKms fakeKms) {
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)));
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(fakeKms.client())
            .grantTokens(GRANT_TOKENS)
            .create();
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));

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

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt skips a Decrypt reply for another key {0}")
    void onDecryptSkipsReplyForAnotherKey(Mpl mpl) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The `KeyId` field in the response MUST equal the configured AWS KMS key identifier.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.
        assertBadReplySkipped(mpl, FakeKms.Reply.decrypt(OTHER_KEY_ARN, bytes(DATA_KEY_LENGTH, 1)), plaintext);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt skips a Decrypt reply plaintext of the wrong length {0}")
    void onDecryptSkipsPlaintextOfWrongLength(Mpl mpl) {
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
        assertBadReplySkipped(mpl, FakeKms.Reply.decrypt(KMS_KEY_ARN, bytes(DATA_KEY_LENGTH / 2, 1)), plaintext);
    }

    @KeyringTest(feature = "aws-kms", name = "[aws-kms] OnDecrypt returns the first data key KMS decrypts {0}")
    void onDecryptReturnsFirstDecryptedDataKey(Mpl mpl, FakeKms fakeKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        DecryptionMaterials decrypted = keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));

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
    private static void assertOnlyMatchingEdkSentToKms(Mpl mpl, FakeKms fakeKms, EncryptedDataKey other) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        fakeKms.reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
        Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
        DecryptionMaterials decrypted = keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(other, edk(2)));
        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        assertDecryptCiphertexts(fakeKms, edk(2));
    }

    /**
     * {@code bad} is a Decrypt reply for EDK 1.
     * With a good reply for EDK 2 after it, OnDecrypt returns EDK 2's data key.
     * With EDK 1 alone, OnDecrypt fails.
     * Each case gets its own FakeKms, so each one starts with only its own replies.
     */
    private static void assertBadReplySkipped(Mpl mpl, FakeKms.Reply bad, byte[] plaintext) {
        // Accepts a good Decrypt reply for the EDK after the bad one
        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, bad)
                .reply(FakeKms.DECRYPT, FakeKms.Reply.decrypt(KMS_KEY_ARN, plaintext));
            Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
            DecryptionMaterials decrypted = keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));
            assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
            assertDecryptCiphertexts(fakeKms, edk(1), edk(2));
        }
        // Rejects a bad Decrypt reply for the only EDK
        try (FakeKms fakeKms = new FakeKms()) {
            fakeKms.reply(FakeKms.DECRYPT, bad);
            Keyring keyring = mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(fakeKms.client()).create();
            keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), List.of(edk(1)), REJECTED_KMS_REPLY_ERROR);
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

    /** A KMS client that calls real KMS in {@code region}. */
    private static KmsClientConfig realKms(String region) {
        return KmsClientConfig.builder().region(region).build();
    }

    /** New encryption materials that already hold {@code dataKey}. */
    private static EncryptionMaterials materialsWithDataKey(Mpl mpl, byte[] dataKey) {
        return mpl.newEncryptionMaterials().toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(dataKey))
            .build();
    }

    /** {@code length} bytes that are the same on every run. Each {@code seed} gives different bytes. */
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
