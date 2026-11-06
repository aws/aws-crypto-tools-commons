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
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.mpl.testserver.client.model.OnDecryptInput;
import aws.cryptography.mpl.testserver.client.model.OnEncryptInput;
import aws.cryptography.testserver.tests.FeatureGate;
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
 * <p>Construction tests make no KMS call. The OnEncrypt and OnDecrypt tests are
 * online: every server needs AWS credentials with KMS GenerateDataKey, Encrypt
 * and Decrypt on KMS_KEY_ARN.
 *
 * <p>The OnDecrypt error tests build valid EDKs with OnEncrypt, then edit or
 * reorder them, and run on one target at a time: the edits, not the server that
 * made the EDKs, are what each test checks.
 */
public class AwsKmsKeyringTest {

    private static final String FEATURE = "aws-kms";

    // The KMS key in the CI-resources account 370957321024 that the
    // hierarchical keyring tests also use.
    // THIS IS A TESTING RESOURCE. DO NOT USE IT IN A PRODUCTION ENVIRONMENT.
    private static final String REGION = "us-west-2";
    private static final String ACCOUNT = "370957321024";
    private static final String KEY_ID = "9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String KMS_KEY_ARN = "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/" + KEY_ID;
    private static final String ALIAS_ARN = "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":alias/x";
    private static final String RAW_ALIAS = "alias/x";
    /** A well-formed key ARN in the same account that names no key. */
    private static final String MISSING_KEY_ARN =
        "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/00000000-0000-0000-0000-000000000000";
    private static final String OTHER_REGION = "us-east-2";

    private static final String PROVIDER_ID = "aws-kms";

    /** Non-signing suites, so the materials carry no signing key. */
    private static final AlgorithmSuiteId SUITE = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
    private static final int DATA_KEY_LENGTH = 32;
    private static final AlgorithmSuiteId AES_128_SUITE = AlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;

    private static final Map<String, String> EC = Map.of("purpose", "aws-kms-keyring-test");
    private static final Map<String, String> OTHER_EC = Map.of("purpose", "another-context");

    /** The upper bound on a KMS ciphertext blob is 6144 bytes. */
    private static final int MAX_CIPHERTEXT_LENGTH = 6144;

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    // -----------------------------------------------------------------------
    // Initialization (aws-kms-keyring.md#initialization)
    // -----------------------------------------------------------------------

    /** A CreateAwsKmsKeyring request that the MPL must reject. */
    record RejectedCase(String name, String kmsKeyId, List<String> grantTokens) {
        @Override
        public String toString() {
            return name;
        }
    }

    static List<RejectedCase> rejectedCases() {
        return List.of(
            new RejectedCase("C1 empty key id", "", List.of()),
            new RejectedCase("C2 non-ASCII character in an ARN",
                "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/9d989aa2-2f9c-438c-a745-cc57d3ad012\u00e9",
                List.of()),
            // A raw alias that is valid apart from its length.
            new RejectedCase("C3 2049-character key id", "alias/" + "a".repeat(2049 - "alias/".length()),
                List.of()),
            new RejectedCase("C4 5-part ARN", "arn:aws:kms:" + REGION + ":" + ACCOUNT, List.of()),
            new RejectedCase("C4 7-part ARN", KMS_KEY_ARN + ":extra", List.of()),
            new RejectedCase("C5 empty partition", "arn::kms:" + REGION + ":" + ACCOUNT + ":key/" + KEY_ID,
                List.of()),
            new RejectedCase("C5 empty region", "arn:aws:kms::" + ACCOUNT + ":key/" + KEY_ID, List.of()),
            new RejectedCase("C5 empty account", "arn:aws:kms:" + REGION + "::key/" + KEY_ID, List.of()),
            new RejectedCase("C6 service s3", "arn:aws:s3:" + REGION + ":" + ACCOUNT + ":key/" + KEY_ID,
                List.of()),
            new RejectedCase("C7 ARN resource foo/x", arn("foo/x"), List.of()),
            new RejectedCase("C7 ARN resource key/", arn("key/"), List.of()),
            new RejectedCase("C7 ARN resource key", arn("key"), List.of()),
            new RejectedCase("C8 raw key/<uuid>", "key/" + KEY_ID, List.of()),
            new RejectedCase("C9 raw foo/bar", "foo/bar", List.of()),
            new RejectedCase("C10 raw alias/", "alias/", List.of()),
            new RejectedCase("C11 eleven grant tokens", KMS_KEY_ARN,
                IntStream.rangeClosed(1, 11).mapToObj(i -> "grant-token-" + i).toList()),
            new RejectedCase("C12 empty grant token", KMS_KEY_ARN, List.of("")),
            new RejectedCase("C12 8193-character grant token", KMS_KEY_ARN, List.of("a".repeat(8193))));
    }

    static Stream<Arguments> rejectedCasesByTarget() {
        return rejectedCases().stream()
            .flatMap(c -> targets().stream().map(target -> Arguments.of(c, target)));
    }

    @ParameterizedTest(name = "[aws-kms] construction rejects {0} {1}")
    @MethodSource("rejectedCasesByTarget")
    void constructionRejected(RejectedCase rejected, LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        assertThrows(MPLClientError.class, () -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(rejected.kmsKeyId())
            .kmsClientRegion(REGION)
            .grantTokens(rejected.grantTokens())
            .build()));
    }

    /** C13: every form of KMS key identifier constructs. */
    @ParameterizedTest(name = "[aws-kms] construction accepts key ARN, alias ARN, raw key id, raw alias {0}")
    @MethodSource("targets")
    void constructionAcceptsEveryIdentifierForm(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        for (String kmsKeyId : List.of(KMS_KEY_ARN, ALIAS_ARN, KEY_ID, RAW_ALIAS)) {
            assertNotNull(createKeyring(client, kmsKeyId, REGION), kmsKeyId);
        }
    }

    // -----------------------------------------------------------------------
    // OnEncrypt (aws-kms-keyring.md#onencrypt)
    // -----------------------------------------------------------------------

    /** Materials without a data key: the keyring calls GenerateDataKey. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt generates a data key {0}")
    @MethodSource("targets")
    void onEncryptGeneratesDataKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        EncryptionMaterials encrypted = onEncrypt(client, keyring(client), initializeEncryption(client, SUITE));

        assertEquals(DATA_KEY_LENGTH, bytes(encrypted.getPlaintextDataKey()).length);
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertKmsEdk(encrypted.getEncryptedDataKeys().get(0));
    }

    /** KMS returns the key ARN, and the keyring writes that, not the raw key id it was built with. */
    @ParameterizedTest(name = "[aws-kms] raw key id keyring writes the key ARN {0}")
    @MethodSource("targets")
    void onEncryptWithRawKeyIdWritesKeyArn(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        EncryptionMaterials encrypted = onEncrypt(client, createKeyring(client, KEY_ID, REGION),
            initializeEncryption(client, SUITE));

        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertKmsEdk(encrypted.getEncryptedDataKeys().get(0));
    }

    /** Materials that already hold a data key: the keyring calls Encrypt and keeps the key. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt wraps an existing data key {0}")
    @MethodSource("targets")
    void onEncryptWrapsExistingDataKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        byte[] dataKey = new byte[DATA_KEY_LENGTH];
        for (int i = 0; i < dataKey.length; i++) {
            dataKey[i] = (byte) i;
        }

        EncryptionMaterials withKey = initializeEncryption(client, SUITE).toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(dataKey))
            .build();
        EncryptionMaterials encrypted = onEncrypt(client, keyring(client), withKey);

        assertArrayEquals(dataKey, bytes(encrypted.getPlaintextDataKey()),
            "wrapping an existing data key must not replace it");
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertKmsEdk(encrypted.getEncryptedDataKeys().get(0));
    }

    /** E1: the KMS call fails, for a key that does not exist and for a client in the wrong region. */
    @ParameterizedTest(name = "[aws-kms] OnEncrypt fails when KMS fails {0}")
    @MethodSource("targets")
    void onEncryptFailsWhenKmsFails(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());

        assertOnEncryptFails(client, createKeyring(client, MISSING_KEY_ARN, REGION));
        assertOnEncryptFails(client, createKeyring(client, KMS_KEY_ARN, OTHER_REGION));
    }

    // -----------------------------------------------------------------------
    // OnDecrypt (aws-kms-keyring.md#ondecrypt)
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[aws-kms] OnEncrypt/OnDecrypt {0}")
    @MethodSource("pairs")
    void onEncryptOnDecryptRoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of(FEATURE), pair);
        MPLTestServerClient enc = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());

        EncryptionMaterials encrypted = onEncrypt(enc, keyring(enc), initializeEncryption(enc, SUITE));
        DecryptionMaterials decrypted = onDecrypt(dec, keyring(dec), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    /** D1: decryption materials that already hold a data key. */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt rejects materials with a data key {0}")
    @MethodSource("targets")
    void onDecryptRejectsMaterialsWithDataKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey valid = validEdk(client);

        DecryptionMaterials withKey = initializeDecryption(client, SUITE, EC).toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(new byte[DATA_KEY_LENGTH]))
            .build();
        String keyringId = keyring(client);
        assertThrows(MPLClientError.class, () -> client.onDecrypt(OnDecryptInput.builder()
            .keyringId(keyringId)
            .materials(withKey)
            .encryptedDataKeys(List.of(valid))
            .build()));
    }

    /** D2: a keyring built from a raw key id cannot decrypt, even an EDK it wrote. */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt rejects a raw key id keyring {0}")
    @MethodSource("targets")
    void onDecryptRejectsRawKeyIdKeyring(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey valid = validEdk(client);

        assertOnDecryptFails(client, createKeyring(client, KEY_ID, REGION), List.of(valid));
    }

    /** D3: a keyring built from an alias, as an ARN or raw, cannot decrypt. */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt rejects alias keyrings {0}")
    @MethodSource("targets")
    void onDecryptRejectsAliasKeyrings(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey valid = validEdk(client);

        assertOnDecryptFails(client, createKeyring(client, ALIAS_ARN, REGION), List.of(valid));
        assertOnDecryptFails(client, createKeyring(client, RAW_ALIAS, REGION), List.of(valid));
    }

    /**
     * D4: an aws-kms EDK whose provider info is not UTF-8 fails the whole
     * decrypt, though a valid EDK follows it.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails on non-UTF-8 provider info {0}")
    @MethodSource("targets")
    void onDecryptFailsOnNonUtf8ProviderInfo(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey valid = validEdk(client);
        EncryptedDataKey nonUtf8 = withProviderInfo(valid, new byte[] {(byte) 0xFF, (byte) 0xFE});

        assertOnDecryptFails(client, keyring(client), List.of(nonUtf8, valid));
    }

    /**
     * D5: an aws-kms EDK whose provider info is not a key ARN fails the whole
     * decrypt, though a valid EDK follows it.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails on provider info that is not an ARN {0}")
    @MethodSource("targets")
    void onDecryptFailsOnProviderInfoThatIsNotAnArn(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey valid = validEdk(client);
        String keyringId = keyring(client);

        for (String info : List.of("not-an-arn", KEY_ID)) {
            EncryptedDataKey notAnArn = withProviderInfo(valid, info.getBytes(StandardCharsets.UTF_8));
            assertOnDecryptFails(client, keyringId, List.of(notAnArn, valid));
        }
    }

    /**
     * D6: no EDK matches the keyring. The keyring compares provider id and
     * provider info as exact, case-sensitive strings.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt fails with no matching EDK {0}")
    @MethodSource("targets")
    void onDecryptFailsWithNoMatchingEdk(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptedDataKey valid = validEdk(client);
        String keyringId = keyring(client);

        List<EncryptedDataKey> nonMatching = List.of(
            withProviderInfo(valid, MISSING_KEY_ARN.getBytes(StandardCharsets.UTF_8)),
            withProviderId(valid, "AWS-KMS"),
            withProviderId(valid, "raw-aes"),
            withProviderInfo(valid, KMS_KEY_ARN.toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8)));
        for (EncryptedDataKey edk : nonMatching) {
            assertOnDecryptFails(client, keyringId, List.of(edk));
        }
    }

    /**
     * D7: a matching EDK whose ciphertext is empty or longer than 6144 bytes
     * fails on its own, and the keyring goes on to the next EDK.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips an EDK with a ciphertext of invalid length {0}")
    @MethodSource("targets")
    void onDecryptSkipsCiphertextOfInvalidLength(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptionMaterials encrypted = onEncrypt(client, keyring(client), initializeEncryption(client, SUITE));
        EncryptedDataKey valid = encrypted.getEncryptedDataKeys().get(0);
        String keyringId = keyring(client);

        for (int length : List.of(0, MAX_CIPHERTEXT_LENGTH + 1)) {
            EncryptedDataKey invalid = withCiphertext(valid, new byte[length]);
            assertOnDecryptFails(client, keyringId, List.of(invalid));
            assertDecryptsTo(encrypted, onDecrypt(client, keyringId, List.of(invalid, valid)));
        }
    }

    /**
     * D8: KMS Decrypt fails for a matching EDK with a garbage ciphertext, and
     * for a valid EDK under a different encryption context. A failed EDK is
     * skipped in favor of the next one.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips an EDK that KMS cannot decrypt {0}")
    @MethodSource("targets")
    void onDecryptSkipsEdkThatKmsCannotDecrypt(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        EncryptionMaterials encrypted = onEncrypt(client, keyring(client), initializeEncryption(client, SUITE));
        EncryptedDataKey valid = encrypted.getEncryptedDataKeys().get(0);
        EncryptedDataKey garbage = withCiphertext(valid, new byte[bytes(valid.getCiphertext()).length]);
        String keyringId = keyring(client);

        assertOnDecryptFails(client, keyringId, List.of(garbage));
        assertDecryptsTo(encrypted, onDecrypt(client, keyringId, List.of(garbage, valid)));

        DecryptionMaterials otherContext = initializeDecryption(client, SUITE, OTHER_EC);
        assertThrows(MPLClientError.class, () -> client.onDecrypt(OnDecryptInput.builder()
            .keyringId(keyringId)
            .materials(otherContext)
            .encryptedDataKeys(List.of(valid))
            .build()));
    }

    /**
     * D10: KMS decrypts an EDK made under an AES-128 suite to a 16-byte key,
     * which is the wrong length for AES-256 materials. The keyring skips that
     * EDK.
     */
    @ParameterizedTest(name = "[aws-kms] OnDecrypt skips a data key of the wrong length {0}")
    @MethodSource("targets")
    void onDecryptSkipsDataKeyOfWrongLength(LanguageServerTarget target) {
        FeatureGate.require(Set.of(FEATURE), target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String keyringId = keyring(client);
        EncryptedDataKey aes128 = onEncrypt(client, keyringId, initializeEncryption(client, AES_128_SUITE))
            .getEncryptedDataKeys().get(0);
        EncryptionMaterials encrypted = onEncrypt(client, keyringId, initializeEncryption(client, SUITE));
        EncryptedDataKey valid = encrypted.getEncryptedDataKeys().get(0);

        assertOnDecryptFails(client, keyringId, List.of(aes128));
        assertDecryptsTo(encrypted, onDecrypt(client, keyringId, List.of(aes128, valid)));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static String arn(String resource) {
        return "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":" + resource;
    }

    /** An aws-kms EDK names the key ARN that KMS returned, as UTF-8. */
    private static void assertKmsEdk(EncryptedDataKey edk) {
        assertEquals(PROVIDER_ID, edk.getKeyProviderId());
        assertArrayEquals(KMS_KEY_ARN.getBytes(StandardCharsets.UTF_8), bytes(edk.getKeyProviderInfo()),
            "key provider info is the key ARN");
    }

    private static void assertDecryptsTo(EncryptionMaterials encrypted, DecryptionMaterials decrypted) {
        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    private static void assertOnEncryptFails(MPLTestServerClient client, String keyringId) {
        EncryptionMaterials materials = initializeEncryption(client, SUITE);
        assertThrows(MPLClientError.class, () -> client.onEncrypt(OnEncryptInput.builder()
            .keyringId(keyringId)
            .materials(materials)
            .build()));
    }

    private static void assertOnDecryptFails(MPLTestServerClient client, String keyringId,
            List<EncryptedDataKey> edks) {
        DecryptionMaterials materials = initializeDecryption(client, SUITE, EC);
        assertThrows(MPLClientError.class, () -> client.onDecrypt(OnDecryptInput.builder()
            .keyringId(keyringId)
            .materials(materials)
            .encryptedDataKeys(edks)
            .build()));
    }

    private static EncryptedDataKey validEdk(MPLTestServerClient client) {
        return onEncrypt(client, keyring(client), initializeEncryption(client, SUITE))
            .getEncryptedDataKeys().get(0);
    }

    private static EncryptedDataKey withProviderId(EncryptedDataKey edk, String providerId) {
        return edk.toBuilder().keyProviderId(providerId).build();
    }

    private static EncryptedDataKey withProviderInfo(EncryptedDataKey edk, byte[] providerInfo) {
        return edk.toBuilder().keyProviderInfo(ByteBuffer.wrap(providerInfo)).build();
    }

    private static EncryptedDataKey withCiphertext(EncryptedDataKey edk, byte[] ciphertext) {
        return edk.toBuilder().ciphertext(ByteBuffer.wrap(ciphertext)).build();
    }

    private static String keyring(MPLTestServerClient client) {
        return createKeyring(client, KMS_KEY_ARN, REGION);
    }

    private static String createKeyring(MPLTestServerClient client, String kmsKeyId, String region) {
        return MplTestServerClients.withRetry(() -> client.createAwsKmsKeyring(CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(kmsKeyId)
            .kmsClientRegion(region)
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

    private static DecryptionMaterials initializeDecryption(MPLTestServerClient client, AlgorithmSuiteId suite,
            Map<String, String> ec) {
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            client.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(ec)
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
        DecryptionMaterials materials = initializeDecryption(client, SUITE, EC);
        DecryptionMaterials out = MplTestServerClients.withRetry(() ->
            client.onDecrypt(OnDecryptInput.builder()
                .keyringId(keyringId)
                .materials(materials)
                .encryptedDataKeys(edks)
                .build())).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
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
