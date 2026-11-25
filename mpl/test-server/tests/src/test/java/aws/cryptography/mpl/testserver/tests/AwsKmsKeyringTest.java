package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
import static aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_NO_KDF;
import static aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
import static aws.cryptography.mpl.testserver.tests.KmsErrors.INVALID_PROVIDER_INFO_ERROR;
import static aws.cryptography.mpl.testserver.tests.KmsErrors.KMS_CALL_FAILED_ERROR;
import static aws.cryptography.mpl.testserver.tests.KmsErrors.KMS_ERROR_CODE;
import static aws.cryptography.mpl.testserver.tests.KmsErrors.REJECTED_KMS_REPLY_ERROR;
import static aws.cryptography.mpl.testserver.tests.KmsErrors.WRONG_REGION_KMS_ERROR;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.ALIAS_ARN;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.KMS_KEY_ARN;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.OTHER_KEY_ARN;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.OTHER_REGION;
import static aws.cryptography.mpl.testserver.tests.KmsKeys.REGION;
import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static aws.cryptography.mpl.testserver.tests.Materials.dataKeyOfLength;
import static aws.cryptography.mpl.testserver.tests.Materials.materialsWithDataKey;
import static aws.cryptography.mpl.testserver.tests.Materials.withProviderInfo;
import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_CONFIGURATION_ERROR;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.KmsClientConfig;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.KmsFixtures;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;

/**
 * Tests for the AWS KMS keyring in aws-kms-keyring.md.
 * This is the keyring for one KMS key, not the discovery or multi-Region (MRK) keyrings.
 *
 * <p>Each test runs once for each language.
 * The test sends keyring calls, such as OnEncrypt, to that language's MPL.
 * Each language has a small server that receives the calls over HTTP and passes them to its MPL.
 *
 * <p>Most tests give the keyring a KMS client that points at {@link MockKms}.
 * MockKms sends back the replies that the test set up, and records each request.
 * So a test can send the keyring a bad reply, or check exactly what the keyring asked KMS.
 * Creating a keyring makes no KMS call.
 * The tests that use {@code realKms} call real KMS.
 * For those, every language's server needs AWS credentials that allow GenerateDataKey, Encrypt and Decrypt on KMS_KEY_ARN.
 */
@KeyringFeature("aws-kms")
public class AwsKmsKeyringTest implements KeyringTestDefaults, KeyringContract {

    private static final String PROVIDER_ID = "aws-kms";
    private static final List<String> GRANT_TOKENS = List.of("grant-token-a", "grant-token-b");

    /** An algorithm suite that does not sign, so the materials hold no signing key. */
    private static final AlgorithmSuiteId ALGORITHM_SUITE = ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
    private static final int DATA_KEY_LENGTH = 32;

    private static final Map<String, String> ENCRYPTION_CONTEXT = Map.of("purpose", "aws-kms-keyring-test");

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

    @KeyringTest(feature = "aws-kms", name = "the KMS key ID must be provided {0}")
    void kmsKeyIdMustBeProvided(Mpl mpl, MockKms mockKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS key identifier

        // AWS KMS key identifier provided: succeeds
        mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create()
            .assertEncryptsAndDecrypts();

        // AWS KMS key identifier not provided: fails
        mpl.awsKmsKeyring()
            .kmsClient(realKms(REGION))
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "the KMS client must be provided {0}")
    void kmsClientMustBeProvided(Mpl mpl, MockKms mockKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MUST provide an AWS KMS SDK client
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS SDK client MUST NOT be null.

        // AWS KMS SDK client provided: succeeds
        mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create()
            .assertEncryptsAndDecrypts();

        // AWS KMS SDK client not provided: fails
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .createFailsWith(INVALID_CONFIGURATION_ERROR)
            .unlessKnownBug("aws-kms-keyring-accepts-missing-kms-client");
    }

    static List<Example<List<String>>> validGrantTokenLists() {
        return KmsFixtures.validGrantTokenLists();
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "grant tokens may be provided {0} {1}",
        inputs = "validGrantTokenLists")
    void grantTokensMayBeProvided(Example<List<String>> grantTokens, Mpl mpl, MockKms mockKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# - MAY provide a list of Grant Tokens

        // a list of Grant Tokens provided: succeeds
        mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .grantTokens(grantTokens.value())
            .create()
            .assertEncryptsAndDecrypts();
    }

    static List<Example<List<String>>> invalidGrantTokenLists() {
        return KmsFixtures.invalidGrantTokenLists();
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "grant tokens must be valid {0} {1}",
        inputs = "invalidGrantTokenLists")
    void grantTokensMustBeValid(Example<List<String>> grantTokens, Mpl mpl, MockKms mockKms) {
        // valid Grant Tokens: succeeds
        mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .grantTokens(GRANT_TOKENS)
            .create()
            .assertEncryptsAndDecrypts();

        // invalid Grant Tokens: fails
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(REGION))
            .grantTokens(grantTokens.value())
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "the KMS key ID must not be empty {0}")
    void kmsKeyIdMustNotBeEmpty(Mpl mpl, MockKms mockKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST NOT be null or empty.

        // not empty: succeeds
        mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create()
            .assertEncryptsAndDecrypts();

        // empty: fails
        mpl.awsKmsKeyring()
            .kmsKeyId("")
            .kmsClient(realKms(REGION))
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    static List<Example<String>> invalidKmsIdentifiers() {
        return KmsFixtures.invalidKmsIdentifiers(KMS_KEY_ARN);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the KMS key ID must be a valid identifier, not {0} {1}",
        inputs = "invalidKmsIdentifiers")
    void kmsKeyIdMustBeValidIdentifier(Example<String> malformed, Mpl mpl, MockKms mockKms) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).

        // a valid identifier: succeeds
        mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
        mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create()
            .assertEncryptsAndDecrypts();

        // not a valid identifier: fails
        mpl.awsKmsKeyring()
            .kmsKeyId(malformed.value())
            .kmsClient(realKms(REGION))
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the KMS key ID may be any valid identifier {0}")
    void kmsKeyIdMayBeAnyValidIdentifier(Mpl mpl) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //= type=test
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).

        // a valid identifier: succeeds
        for (Example<String> kmsKeyId : KmsFixtures.validKmsIdentifiers(KMS_KEY_ARN)) {
            try (MockKms mockKms = new MockKms()) {
                mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
                Keyring keyring = mpl.awsKmsKeyring()
                    .kmsKeyId(kmsKeyId.value())
                    .kmsClient(mockKms.client())
                    .create();
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

    /** MockKms replies with a different key than the keyring's own, and the EDK must record the key from the reply. */
    @KeyringTest(
        feature = "aws-kms",
        name = "OnEncrypt without a data key calls GenerateDataKey {0}")
    void onEncryptWithoutDataKeyCallsGenerateDataKey(Mpl mpl, MockKms mockKms) {
        // materials do not contain a plaintext data key: succeeds
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        byte[] ciphertext = bytes(64, 2);

        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();
        mockKms.nextGenerateDataKeyReturns(OTHER_KEY_ARN, plaintext, ciphertext);
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());

        assertEquals(0, mockKms.encryptCalls().size());
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key
        //# OnEncrypt MUST attempt to generate a new plaintext data key
        //# by calling [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).
        assertEquals(1, mockKms.generateDataKeyCalls().size());
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
        for (Example<String> kmsKeyId : KmsFixtures.validKmsIdentifiers(KMS_KEY_ARN)) {
            cases.add(new RequestCase(kmsKeyId.value(), ALG_AES_128_GCM_IV12_TAG16_NO_KDF, 16));
            cases.add(new RequestCase(kmsKeyId.value(), ALG_AES_192_GCM_IV12_TAG16_NO_KDF, 24));
            cases.add(new RequestCase(kmsKeyId.value(), ALG_AES_256_GCM_IV12_TAG16_NO_KDF, 32));
        }
        return cases;
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "GenerateDataKey request {0} {1}",
        inputs = "requestCases")
    void generateDataKeyRequest(RequestCase requestCase, Mpl mpl, MockKms mockKms) {
        // request: sent
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(requestCase.kmsKeyId())
            .kmsClient(mockKms.client())
            .grantTokens(GRANT_TOKENS)
            .create();
        mockKms.nextGenerateDataKeyReturns(KMS_KEY_ARN, dataKeyOfLength(requestCase.dataKeyLength()));
        keyring.onEncrypt(mpl.newEncryptionMaterials(requestCase.suite()));

        List<MockKms.Request> requests = mockKms.generateDataKeyCalls();
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The keyring MUST call AWS KMS GenerateDataKeys with a request constructed as follows:
        assertEquals(1, requests.size());
        MockKms.Request request = requests.get(0);
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

    @KeyringTest(feature = "aws-kms", name = "OnEncrypt fails when GenerateDataKey fails {0}")
    void onEncryptFailsWhenGenerateDataKeyFails(Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the call to [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
        //# OnEncrypt MUST NOT modify the [encryption materials](../structures.md#encryption-materials) and MUST fail.

        // the call succeeds
        mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onEncrypt(mpl.newEncryptionMaterials());

        // the call does not succeed: fails
        mockKms.nextGenerateDataKeyFailsWith(KMS_ERROR_CODE);
        keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), KMS_CALL_FAILED_ERROR);
    }

    static List<Example<Integer>> wrongPlaintextLengths() {
        return KmsFixtures.wrongPlaintextLengths(DATA_KEY_LENGTH);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the GenerateDataKey plaintext length must match the suite, not {0} bytes {1}",
        inputs = "wrongPlaintextLengths")
    void generateDataKeyPlaintextLengthMustMatchSuite(Example<Integer> length, Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that the response `Plaintext` length matches
        //# the specification of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.

        // `Plaintext` length matches: succeeds
        mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onEncrypt(mpl.newEncryptionMaterials());

        // `Plaintext` length does not match: fails
        mockKms.nextGenerateDataKeyReturns(KMS_KEY_ARN, dataKeyOfLength(length.value()));
        keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), REJECTED_KMS_REPLY_ERROR);
    }

    /** KeyIds for a KMS reply that are not any form of KMS identifier. */
    static List<Example<String>> garbageReplyKeyIds() {
        return KmsFixtures.garbageReplyKeyIds(KMS_KEY_ARN);
    }

    /** KeyIds for a KMS reply that are KMS identifiers, but not key ARNs. */
    static List<Example<String>> nonArnReplyKeyIds() {
        return KmsFixtures.nonArnReplyKeyIds(KMS_KEY_ARN);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the GenerateDataKey reply KeyId must be a key ARN, not {0} {1}",
        inputs = "garbageReplyKeyIds")
    void generateDataKeyReplyKeyIdMustBeKeyArn(Example<String> keyId, Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).

        // `KeyId` is a valid AWS KMS key ARN: succeeds
        mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onEncrypt(mpl.newEncryptionMaterials());

        // `KeyId` is not a valid AWS KMS key ARN: fails
        mockKms.nextGenerateDataKeyReturnsDataKeyFor(keyId.value());
        keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), REJECTED_KMS_REPLY_ERROR);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the GenerateDataKey reply KeyId must be a key ARN, not {0} {1}",
        inputs = "nonArnReplyKeyIds")
    void generateDataKeyReplyKeyIdMustBeKeyArnNotOtherIdentifier(Example<String> keyId, Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();
        EncryptionMaterials materials = mpl.newEncryptionMaterials();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The Generate Data Key response’s `KeyId` MUST be [a valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).

        // `KeyId` is a valid AWS KMS key ARN: succeeds
        mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onEncrypt(mpl.newEncryptionMaterials());

        // `KeyId` is not a valid AWS KMS key ARN: fails
        mockKms.nextGenerateDataKeyReturnsDataKeyFor(keyId.value());
        keyring.onEncryptFailsWith(materials, REJECTED_KMS_REPLY_ERROR)
            .unlessKnownBug("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn");
    }

    // -----------------------------------------------------------------------
    // OnEncrypt, materials with a data key: Encrypt
    // -----------------------------------------------------------------------

    static List<String> kmsKeyIdForms() {
        return KmsFixtures.validKmsIdentifiers(KMS_KEY_ARN).stream()
            .map(kmsKeyId -> kmsKeyId.value())
            .toList();
    }

    /** MockKms replies with a different key than the keyring's own, and the EDK must record the key from the reply. */
    @KeyringTest(
        feature = "aws-kms",
        name = "OnEncrypt with a data key calls Encrypt {0} {1}",
        inputs = "kmsKeyIdForms")
    void onEncryptWithDataKeyCallsEncrypt(String kmsKeyId, Mpl mpl, MockKms mockKms) {
        // materials do contain a plaintext data key: succeeds
        byte[] dataKey = bytes(DATA_KEY_LENGTH, 3);
        byte[] ciphertext = bytes(64, 4);

        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(kmsKeyId)
            .kmsClient(mockKms.client())
            .grantTokens(GRANT_TOKENS)
            .create();
        mockKms.nextEncryptReturns(OTHER_KEY_ARN, ciphertext);
        EncryptionMaterials encrypted = keyring.onEncrypt(
            materialsWithDataKey(mpl.newEncryptionMaterials(), dataKey));

        assertEquals(0, mockKms.generateDataKeyCalls().size());
        List<MockKms.Request> requests = mockKms.encryptCalls();
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
        MockKms.Request request = requests.get(0);
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

    @KeyringTest(feature = "aws-kms", name = "OnEncrypt fails when Encrypt fails {0}")
    void onEncryptFailsWhenEncryptFails(Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.

        // the call succeeds
        mockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN);
        keyring.onEncrypt(materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)));

        // the call does not succeed: fails
        mockKms.nextEncryptFailsWith(KMS_ERROR_CODE);
        keyring.onEncryptFailsWith(
            materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)),
            KMS_CALL_FAILED_ERROR);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the Encrypt reply KeyId must be a key ARN, not {0} {1}",
        inputs = "garbageReplyKeyIds")
    void encryptReplyKeyIdMustBeKeyArn(Example<String> keyId, Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).

        // `KeyId` is a valid AWS KMS key ARN: succeeds
        mockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN);
        keyring.onEncrypt(materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)));

        // `KeyId` is not a valid AWS KMS key ARN: fails
        mockKms.nextEncryptReturnsCiphertextFor(keyId.value());
        keyring.onEncryptFailsWith(
            materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)),
            REJECTED_KMS_REPLY_ERROR);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the Encrypt reply KeyId must be a key ARN, not {0} {1}",
        inputs = "nonArnReplyKeyIds")
    void encryptReplyKeyIdMustBeKeyArnNotOtherIdentifier(Example<String> keyId, Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();
        EncryptionMaterials materials = materialsWithDataKey(
            mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3));

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).

        // `KeyId` is a valid AWS KMS key ARN: succeeds
        mockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN);
        keyring.onEncrypt(materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)));

        // `KeyId` is not a valid AWS KMS key ARN: fails
        mockKms.nextEncryptReturnsCiphertextFor(keyId.value());
        keyring.onEncryptFailsWith(materials, REJECTED_KMS_REPLY_ERROR)
            .unlessKnownBug("aws-kms-keyring-accepts-reply-key-id-that-is-not-a-key-arn");
    }

    // -----------------------------------------------------------------------
    // The KMS client that the keyring was given, with real KMS
    //
    // A us-east-2 KMS client cannot use a us-west-2 key.
    // Each test makes the same call twice.
    // Through a us-west-2 client the call works, which shows that the server's AWS credentials work.
    // Through a us-east-2 client it fails, which happens only if the keyring uses the client it was given.
    // -----------------------------------------------------------------------

    @KeyringTest(
        feature = "aws-kms",
        name = "GenerateDataKey uses the configured client {0}")
    void generateDataKeyUsesConfiguredClient(Mpl mpl) {
        Keyring usWest2Keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(REGION))
            .create();
        Keyring usEast2Keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(OTHER_REGION))
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.

        // configured AWS KMS client can use the key: succeeds
        usWest2Keyring.onEncrypt(mpl.newEncryptionMaterials());

        // configured AWS KMS client cannot use the key: fails
        usEast2Keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), WRONG_REGION_KMS_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "Encrypt uses the configured client {0}")
    void encryptUsesConfiguredClient(Mpl mpl) {
        Keyring usWest2Keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(REGION))
            .create();
        Keyring usEast2Keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(OTHER_REGION))
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.

        // configured AWS KMS client can use the key: succeeds
        usWest2Keyring.onEncrypt(
            materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)));

        // configured AWS KMS client cannot use the key: fails
        usEast2Keyring.onEncryptFailsWith(
            materialsWithDataKey(mpl.newEncryptionMaterials(), bytes(DATA_KEY_LENGTH, 3)),
            WRONG_REGION_KMS_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "Decrypt uses the configured client {0}")
    void decryptUsesConfiguredClient(Mpl mpl) {
        Keyring usWest2Keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(REGION))
            .create();
        Keyring usEast2Keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(realKms(OTHER_REGION))
            .create();
        List<EncryptedDataKey> edks = usWest2Keyring.onEncrypt(mpl.newEncryptionMaterials())
            .getEncryptedDataKeys();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
        //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.

        // configured AWS KMS client can use the key: succeeds
        usWest2Keyring.onDecrypt(mpl.newDecryptionMaterials(), edks);

        // configured AWS KMS client cannot use the key: fails
        usEast2Keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), edks, WRONG_REGION_KMS_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "one language encrypts and another decrypts with real KMS {0}", pairs = true)
    void roundTripWithRealKms(Mpl encryptingMpl, Mpl decryptingMpl) {
        // one language encrypts, another language decrypts: succeeds
        Keyring encryptingKeyring =
            encryptingMpl.awsKmsKeyring()
                .kmsKeyId(KMS_KEY_ARN)
                .kmsClient(realKms(REGION))
                .create();
        EncryptionMaterials encrypted = encryptingKeyring.onEncrypt(encryptingMpl.newEncryptionMaterials());
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        Keyring decryptingKeyring =
            decryptingMpl.awsKmsKeyring()
                .kmsKeyId(KMS_KEY_ARN)
                .kmsClient(realKms(REGION))
                .create();
        DecryptionMaterials decrypted =
            decryptingKeyring.onDecrypt(
                decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    // -----------------------------------------------------------------------
    // Checks every keyring must pass
    // -----------------------------------------------------------------------

    /**
     * The MockKms for the {@link KeyringContract} tests, which never see it.
     * {@link #workingKeyring} starts it, and {@link #stopContractMockKms} stops it after the test.
     */
    private MockKms contractMockKms;

    /**
     * A keyring for KMS_KEY_ARN on MockKms, with the KMS replies that any one {@link KeyringContract} test needs.
     * No test uses every reply, and a reply that is never used does no harm.
     * The second Decrypt reply is there for a keyring that wrongly sends KMS an EDK it should skip.
     * That call then succeeds, so the test that expects OnDecrypt to fail catches it.
     */
    @Override
    public Keyring workingKeyring(Mpl mpl) {
        if (contractMockKms == null) {
            contractMockKms = new MockKms();
        }
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(contractMockKms.client())
            .create();
        contractMockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
        contractMockKms.nextEncryptReturnsCiphertextFor(KMS_KEY_ARN);
        contractMockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        contractMockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        return keyring;
    }

    /** One EDK for another provider and one for another key. */
    @Override
    public List<EncryptedDataKey> edksThatDontMatch() {
        return List.of(
            edk(1).toBuilder().keyProviderId("raw-aes").build(),
            withProviderInfo(edk(2), OTHER_KEY_ARN.getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    void stopContractMockKms() {
        if (contractMockKms != null) {
            contractMockKms.close();
        }
    }

    @Override
    @KeyringTest
    public void keepsAnExistingDataKeyOnEncrypt(Mpl mpl) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //= type=test
        //# If the input [encryption materials](../structures.md#encryption-materials) do contain a plaintext data key,
        //# OnEncrypt MUST attempt to encrypt the plaintext data key using the configured AWS KMS key identifier.
        KeyringContract.super.keepsAnExistingDataKeyOnEncrypt(mpl);
    }

    @Override
    @KeyringTest
    public void rejectsDecryptionMaterialsThatHaveADataKey(Mpl mpl) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key
        //# OnDecrypt MUST return an error.
        KeyringContract.super.rejectsDecryptionMaterialsThatHaveADataKey(mpl);
    }

    @Override
    @KeyringTest
    public void failsWhenNoEdkMatches(Mpl mpl) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
        //# then it MUST yield an error that includes all the collected errors.
        KeyringContract.super.failsWhenNoEdkMatches(mpl);
    }

    // -----------------------------------------------------------------------
    // OnDecrypt
    // -----------------------------------------------------------------------

    static List<Example<String>> otherProviderIds() {
        return KmsFixtures.otherProviderIds();
    }

    /**
     * An EDK for another provider or key, then an EDK for this keyring's key.
     * Only the second one may reach KMS.
     * MockKms has one reply, so a keyring that sent both would see its second call fail.
     */
    @KeyringTest(
        feature = "aws-kms",
        name = "the provider ID must match aws-kms, not {0} {1}",
        inputs = "otherProviderIds")
    void providerIdMustMatchAwsKms(Example<String> providerId, Mpl mpl, MockKms mockKms) {
        EncryptedDataKey other = edk(1).toBuilder().keyProviderId(providerId.value()).build();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - Its provider ID MUST exactly match the value “aws-kms”.

        // first provider ID does not match "aws-kms", second does: succeeds
        assertOnlyMatchingEdkSentToKms(mpl, mockKms, other);
    }

    static List<Example<String>> otherProviderInfos() {
        return KmsFixtures.otherProviderInfos(KMS_KEY_ARN);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the provider info must match the KMS key ID, not {0} {1}",
        inputs = "otherProviderInfos")
    void providerInfoMustMatchKmsKeyId(Example<String> providerInfo, Mpl mpl, MockKms mockKms) {
        EncryptedDataKey other = withProviderInfo(
            edk(1), providerInfo.value().getBytes(StandardCharsets.UTF_8));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST match the configured AWS KMS key identifier.

        // first provider info does not match, second does: succeeds
        assertOnlyMatchingEdkSentToKms(mpl, mockKms, other);
    }

    static List<Example<byte[]>> nonArnProviderInfos() {
        return KmsFixtures.nonArnProviderInfos(KMS_KEY_ARN);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the provider info must be a key ARN, not {0} {1}",
        inputs = "nonArnProviderInfos")
    void providerInfoMustBeKeyArn(Example<byte[]> info, Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.

        // provider info is a valid AWS KMS ARN with a resource type of `key`: succeeds
        mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));

        // provider info is not a valid AWS KMS ARN: fails
        // This reply lets a keyring that skips the bad EDK decrypt EDK 2, so the test catches it.
        mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(),
            List.of(withProviderInfo(edk(1), info.value()), edk(2)), INVALID_PROVIDER_INFO_ERROR);
    }

    @KeyringTest(feature = "aws-kms", name = "the provider info must not be an alias ARN {0}")
    void providerInfoMustNotBeAliasArn(Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();
        List<EncryptedDataKey> edks =
            List.of(withProviderInfo(edk(1), ALIAS_ARN.getBytes(StandardCharsets.UTF_8)), edk(2));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of `key` or OnDecrypt MUST fail.

        // provider info is a valid AWS KMS ARN with a resource type of `key`: succeeds
        mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));

        // provider info resource type is not `key`: fails
        // This reply lets a keyring that skips the alias EDK decrypt EDK 2, so the test catches it.
        mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), edks, INVALID_PROVIDER_INFO_ERROR)
            .unlessKnownBug("aws-kms-keyring-skips-alias-arn-provider-info");
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "OnDecrypt attempts each EDK one at a time {0}")
    void onDecryptAttemptsEachEdkOneAtATime(Mpl mpl, MockKms mockKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        // first fails, second succeeds: succeeds
        mockKms.nextDecryptFailsWith(KMS_ERROR_CODE);
        mockKms.nextDecryptReturns(KMS_KEY_ARN, plaintext);
        DecryptionMaterials decrypted = keyring.onDecrypt(
            mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));

        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
        assertDecryptCiphertexts(mockKms, edk(1), edk(2));
    }

    @KeyringTest(feature = "aws-kms", name = "OnDecrypt yields all the collected errors {0}")
    void onDecryptYieldsAllCollectedErrors(Mpl mpl, MockKms mockKms) {
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();
        DecryptionMaterials materials = mpl.newDecryptionMaterials();

        // decrypt an encrypted data key: succeeds
        mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));

        // fails to successfully decrypt any encrypted data key: fails
        mockKms.nextDecryptFailsWith(KMS_ERROR_CODE);
        mockKms.nextDecryptFailsWith(KMS_ERROR_CODE);
        mockKms.nextDecryptFailsWith(KMS_ERROR_CODE);
        MPLClientError error =
            keyring.onDecryptFailsWith(
                materials, List.of(edk(1), edk(2), edk(3)), KMS_CALL_FAILED_ERROR).error();
        assertEquals(4, mockKms.decryptCalls().size());
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

    @KeyringTest(feature = "aws-kms", name = "Decrypt request {0}")
    void decryptRequest(Mpl mpl, MockKms mockKms) {
        // request: sent
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .grantTokens(GRANT_TOKENS)
            .create();
        mockKms.nextDecryptReturnsDataKeyFor(KMS_KEY_ARN);
        keyring.onDecrypt(mpl.newDecryptionMaterials(), List.of(edk(1)));

        List<MockKms.Request> requests = mockKms.decryptCalls();
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), the keyring MUST call with a request constructed as follows:
        assertEquals(1, requests.size());
        MockKms.Request request = requests.get(0);
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

    @KeyringTest(feature = "aws-kms", name = "the Decrypt reply KeyId must equal the KMS key ID {0}")
    void decryptReplyKeyIdMustEqualKmsKeyId(Mpl mpl, MockKms mockKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The `KeyId` field in the response MUST equal the configured AWS KMS key identifier.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.

        // first `KeyId` does not equal, second does: succeeds
        mockKms.nextDecryptReturnsDataKeyFor(OTHER_KEY_ARN);
        mockKms.nextDecryptReturns(KMS_KEY_ARN, plaintext);
        DecryptionMaterials decrypted = keyring.onDecrypt(
            mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));
        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        assertDecryptCiphertexts(mockKms, edk(1), edk(2));

        // `KeyId` does not equal: fails
        mockKms.nextDecryptReturnsDataKeyFor(OTHER_KEY_ARN);
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), List.of(edk(1)), REJECTED_KMS_REPLY_ERROR);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "the Decrypt reply plaintext length must match the suite {0}")
    void decryptReplyPlaintextLengthMustMatchSuite(Mpl mpl, MockKms mockKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 2);
        byte[] halfLengthPlaintext = dataKeyOfLength(DATA_KEY_LENGTH / 2);
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - The length of the response’s `Plaintext` MUST equal the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
        //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [decryption materials](../structures.md#decryption-materials).
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# If the response does not satisfies these requirements then an error MUST be collected
        //# and the next encrypted data key in the filtered set MUST be attempted.

        // first `Plaintext` length does not equal, second does: succeeds
        mockKms.nextDecryptReturns(KMS_KEY_ARN, halfLengthPlaintext);
        mockKms.nextDecryptReturns(KMS_KEY_ARN, plaintext);
        DecryptionMaterials decrypted = keyring.onDecrypt(
            mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));
        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        assertDecryptCiphertexts(mockKms, edk(1), edk(2));

        // `Plaintext` length does not equal: fails
        mockKms.nextDecryptReturns(KMS_KEY_ARN, halfLengthPlaintext);
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), List.of(edk(1)), REJECTED_KMS_REPLY_ERROR);
    }

    @KeyringTest(
        feature = "aws-kms",
        name = "OnDecrypt returns immediately after the first data key decrypts {0}")
    void onDecryptReturnsImmediately(Mpl mpl, MockKms mockKms) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);

        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();

        // first encrypted data key decrypts: succeeds
        mockKms.nextDecryptReturns(KMS_KEY_ARN, plaintext);
        DecryptionMaterials decrypted = keyring.onDecrypt(
            mpl.newDecryptionMaterials(), List.of(edk(1), edk(2)));

        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - MUST set the plaintext data key on the [decryption materials](../structures.md#decryption-materials) as the response `Plaintext`.
        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=test
        //# - MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).
        assertDecryptCiphertexts(mockKms, edk(1));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * An aws-kms EDK for this keyring's key.
     * Each {@code seed} gives a different ciphertext, so the tests can tell EDKs apart.
     */
    private static EncryptedDataKey edk(int seed) {
        return Materials.edk(PROVIDER_ID, KMS_KEY_ARN, seed);
    }

    /** {@code other}, then an EDK for this keyring's key: OnDecrypt succeeds and sends only the second one to KMS. */
    private static void assertOnlyMatchingEdkSentToKms(Mpl mpl, MockKms mockKms, EncryptedDataKey other) {
        byte[] plaintext = bytes(DATA_KEY_LENGTH, 1);
        Keyring keyring = mpl.awsKmsKeyring()
            .kmsKeyId(KMS_KEY_ARN)
            .kmsClient(mockKms.client())
            .create();
        mockKms.nextDecryptReturns(KMS_KEY_ARN, plaintext);
        DecryptionMaterials decrypted = keyring.onDecrypt(
            mpl.newDecryptionMaterials(), List.of(other, edk(2)));
        assertArrayEquals(plaintext, bytes(decrypted.getPlaintextDataKey()));
        assertDecryptCiphertexts(mockKms, edk(2));
    }

    /** MockKms got one Decrypt request for each EDK given, in that order. */
    private static void assertDecryptCiphertexts(MockKms mockKms, EncryptedDataKey... edks) {
        List<MockKms.Request> requests = mockKms.decryptCalls();
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
}
