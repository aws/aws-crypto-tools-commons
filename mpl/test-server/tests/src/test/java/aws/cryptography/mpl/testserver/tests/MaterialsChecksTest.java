package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.PUBLIC_KEY_EC_KEY;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.CreateDefaultCmmInput;
import aws.cryptography.mpl.testserver.client.model.CreateStaticKeyringInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * What the Default CMM does with the materials its keyring returns.
 *
 * <p>The keyring is a static keyring that returns fixed materials. The Default
 * CMM rejects them unless they are the materials it handed the keyring with a
 * data key added: the Dafny MPL's ValidEncryptionMaterialsTransition,
 * EncryptionMaterialsHasPlaintextDataKey and DecryptionMaterialsTransitionIsValid
 * (DefaultCMM.dfy).
 *
 * <p>The Default CMM hands the keyring the request's algorithm suite and
 * encryption context, no required encryption context keys, and no data key.
 * For a signing suite on decrypt, it also hands the verification key from the
 * context.
 */
public class MaterialsChecksTest {

    private static final Set<String> FEATURES = Set.of("static-keyring", "default-cmm");

    private static final AlgorithmSuiteId SUITE = AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final AlgorithmSuiteId OTHER_SUITE = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    private static final AlgorithmSuiteId SIGNING_SUITE =
        AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    private static final CommitmentPolicy POLICY = CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT;

    private static final Map<String, String> EC = Map.of("purpose", "materials-checks");
    private static final byte[] DATA_KEY = new byte[32];

    static {
        for (int i = 0; i < DATA_KEY.length; i++) DATA_KEY[i] = (byte) (i + 1);
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    private static EncryptedDataKey edk() {
        return EncryptedDataKey.builder()
            .keyProviderId("static")
            .keyProviderInfo(ByteBuffer.wrap("static".getBytes()))
            .ciphertext(ByteBuffer.wrap("static".getBytes()))
            .build();
    }

    /** The materials the Default CMM hands the keyring on encrypt, with a data key added. */
    private static EncryptionMaterials.Builder encryptionMaterials() {
        return EncryptionMaterials.builder()
            .algorithmSuiteId(SUITE)
            .encryptionContext(EC)
            .encryptedDataKeys(List.of(edk()))
            .requiredEncryptionContextKeys(List.of())
            .plaintextDataKey(ByteBuffer.wrap(DATA_KEY));
    }

    /** The materials the Default CMM hands the keyring on decrypt, with a data key added. */
    private static DecryptionMaterials.Builder decryptionMaterials() {
        return DecryptionMaterials.builder()
            .algorithmSuiteId(SUITE)
            .encryptionContext(EC)
            .requiredEncryptionContextKeys(List.of())
            .plaintextDataKey(ByteBuffer.wrap(DATA_KEY));
    }

    private static Map<String, String> with(Map<String, String> ec, String key, String value) {
        Map<String, String> out = new HashMap<>(ec);
        out.put(key, value);
        return out;
    }

    /** @return a Default CMM over a static keyring returning {@code encryption} and {@code decryption}. */
    private static String createCmm(MPLTestServerClient client, EncryptionMaterials encryption,
            DecryptionMaterials decryption) {
        CreateStaticKeyringInput.Builder keyring = CreateStaticKeyringInput.builder();
        if (encryption != null) keyring.encryptionMaterials(encryption);
        if (decryption != null) keyring.decryptionMaterials(decryption);
        String keyringId = MplTestServerClients.withRetry(() ->
            client.createStaticKeyring(keyring.build())).getKeyringId();
        return MplTestServerClients.withRetry(() ->
            client.createDefaultCmm(CreateDefaultCmmInput.builder().keyringId(keyringId).build())).getCmmId();
    }

    private static GetEncryptionMaterialsInput getEncryptionMaterials(String cmmId) {
        return GetEncryptionMaterialsInput.builder()
            .cmmId(cmmId)
            .encryptionContext(EC)
            .commitmentPolicy(POLICY)
            .algorithmSuiteId(SUITE)
            .build();
    }

    private static DecryptMaterialsInput decryptMaterials(String cmmId, AlgorithmSuiteId suite,
            Map<String, String> ec) {
        return DecryptMaterialsInput.builder()
            .cmmId(cmmId)
            .algorithmSuiteId(suite)
            .encryptedDataKeys(List.of(edk()))
            .encryptionContext(ec)
            .commitmentPolicy(POLICY)
            .build();
    }

    /** A Default CMM on {@code target} whose keyring returns {@code materials} from OnEncrypt. */
    private static void assertEncryptRejected(LanguageServerTarget target, EncryptionMaterials materials) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, materials, null);
        assertThrows(MPLClientError.class, () -> client.getEncryptionMaterials(getEncryptionMaterials(cmmId)));
    }

    /** A Default CMM on {@code target} whose keyring returns {@code materials} from OnDecrypt. */
    private static void assertDecryptRejected(LanguageServerTarget target, DecryptionMaterials materials,
            AlgorithmSuiteId suite, Map<String, String> ec) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, null, materials);
        assertThrows(MPLClientError.class, () -> client.decryptMaterials(decryptMaterials(cmmId, suite, ec)));
    }

    /** A P-384 verification key as an X9.62 compressed point, the form the context carries. */
    private static byte[] verificationKey() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
        BigInteger x = key.getW().getAffineX();
        BigInteger y = key.getW().getAffineY();
        byte[] out = new byte[49];
        out[0] = (byte) (y.testBit(0) ? 0x03 : 0x02);
        byte[] xBytes = x.toByteArray();
        int copy = Math.min(xBytes.length, 48);
        System.arraycopy(xBytes, xBytes.length - copy, out, 49 - copy, copy);
        return out;
    }

    // -----------------------------------------------------------------------
    // GetEncryptionMaterials
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[materials-checks] encrypt accepts an added data key {0}")
    @MethodSource("targets")
    void encryptAcceptsAddedDataKey(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, encryptionMaterials().build(), null);

        GetEncryptionMaterialsOutput out = MplTestServerClients.withRetry(() ->
            client.getEncryptionMaterials(getEncryptionMaterials(cmmId)));

        assertArrayEquals(DATA_KEY, bytes(out.getPlaintextDataKey()));
        assertEquals(1, out.getEncryptedDataKeys().size());
        assertEquals("static", out.getEncryptedDataKeys().get(0).getKeyProviderId());
    }

    @ParameterizedTest(name = "[materials-checks] encrypt rejects no data key {0}")
    @MethodSource("targets")
    void encryptRejectsNoDataKey(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, null, null);
        assertThrows(MPLClientError.class, () -> client.getEncryptionMaterials(getEncryptionMaterials(cmmId)));
    }

    @ParameterizedTest(name = "[materials-checks] encrypt rejects no encrypted data keys {0}")
    @MethodSource("targets")
    void encryptRejectsNoEncryptedDataKeys(LanguageServerTarget target) {
        assertEncryptRejected(target, encryptionMaterials().encryptedDataKeys(List.of()).build());
    }

    @ParameterizedTest(name = "[materials-checks] encrypt rejects a changed algorithm suite {0}")
    @MethodSource("targets")
    void encryptRejectsChangedSuite(LanguageServerTarget target) {
        assertEncryptRejected(target, encryptionMaterials().algorithmSuiteId(OTHER_SUITE).build());
    }

    @ParameterizedTest(name = "[materials-checks] encrypt rejects a changed encryption context {0}")
    @MethodSource("targets")
    void encryptRejectsChangedContext(LanguageServerTarget target) {
        assertEncryptRejected(target,
            encryptionMaterials().encryptionContext(with(EC, "added", "by keyring")).build());
    }

    @ParameterizedTest(name = "[materials-checks] encrypt rejects changed required context keys {0}")
    @MethodSource("targets")
    void encryptRejectsChangedRequiredKeys(LanguageServerTarget target) {
        assertEncryptRejected(target,
            encryptionMaterials().requiredEncryptionContextKeys(List.of("purpose")).build());
    }

    // -----------------------------------------------------------------------
    // DecryptMaterials
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "[materials-checks] decrypt accepts an added data key {0}")
    @MethodSource("targets")
    void decryptAcceptsAddedDataKey(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, null, decryptionMaterials().build());

        DecryptMaterialsOutput out = MplTestServerClients.withRetry(() ->
            client.decryptMaterials(decryptMaterials(cmmId, SUITE, EC)));

        assertArrayEquals(DATA_KEY, bytes(out.getPlaintextDataKey()));
    }

    @ParameterizedTest(name = "[materials-checks] decrypt rejects no data key {0}")
    @MethodSource("targets")
    void decryptRejectsNoDataKey(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, null, null);
        assertThrows(MPLClientError.class, () -> client.decryptMaterials(decryptMaterials(cmmId, SUITE, EC)));
    }

    @ParameterizedTest(name = "[materials-checks] decrypt rejects a changed algorithm suite {0}")
    @MethodSource("targets")
    void decryptRejectsChangedSuite(LanguageServerTarget target) {
        assertDecryptRejected(target, decryptionMaterials().algorithmSuiteId(OTHER_SUITE).build(), SUITE, EC);
    }

    @ParameterizedTest(name = "[materials-checks] decrypt rejects a changed encryption context {0}")
    @MethodSource("targets")
    void decryptRejectsChangedContext(LanguageServerTarget target) {
        assertDecryptRejected(target,
            decryptionMaterials().encryptionContext(with(EC, "added", "by keyring")).build(), SUITE, EC);
    }

    @ParameterizedTest(name = "[materials-checks] decrypt rejects changed required context keys {0}")
    @MethodSource("targets")
    void decryptRejectsChangedRequiredKeys(LanguageServerTarget target) {
        assertDecryptRejected(target,
            decryptionMaterials().requiredEncryptionContextKeys(List.of("purpose")).build(), SUITE, EC);
    }

    @ParameterizedTest(name = "[materials-checks] decrypt accepts a data key for a signing suite {0}")
    @MethodSource("targets")
    void decryptAcceptsSigningSuiteDataKey(LanguageServerTarget target) throws GeneralSecurityException {
        FeatureGate.require(FEATURES, target);
        byte[] verificationKey = verificationKey();
        Map<String, String> ec = with(EC, PUBLIC_KEY_EC_KEY, Base64.getEncoder().encodeToString(verificationKey));
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client, null, decryptionMaterials()
            .algorithmSuiteId(SIGNING_SUITE)
            .encryptionContext(ec)
            .verificationKey(ByteBuffer.wrap(verificationKey))
            .build());

        DecryptMaterialsOutput out = MplTestServerClients.withRetry(() ->
            client.decryptMaterials(decryptMaterials(cmmId, SIGNING_SUITE, ec)));

        assertArrayEquals(DATA_KEY, bytes(out.getPlaintextDataKey()));
        assertArrayEquals(verificationKey, bytes(out.getVerificationKey()));
    }

    @ParameterizedTest(name = "[materials-checks] decrypt rejects a changed verification key {0}")
    @MethodSource("targets")
    void decryptRejectsChangedVerificationKey(LanguageServerTarget target) throws GeneralSecurityException {
        byte[] verificationKey = verificationKey();
        Map<String, String> ec = with(EC, PUBLIC_KEY_EC_KEY, Base64.getEncoder().encodeToString(verificationKey));
        assertDecryptRejected(target, decryptionMaterials()
            .algorithmSuiteId(SIGNING_SUITE)
            .encryptionContext(ec)
            .verificationKey(ByteBuffer.wrap(verificationKey()))
            .build(), SIGNING_SUITE, ec);
    }

    @ParameterizedTest(name = "[materials-checks] decrypt rejects a signing suite with no verification key {0}")
    @MethodSource("targets")
    void decryptRejectsMissingVerificationKey(LanguageServerTarget target) throws GeneralSecurityException {
        Map<String, String> ec = with(EC, PUBLIC_KEY_EC_KEY, Base64.getEncoder().encodeToString(verificationKey()));
        assertDecryptRejected(target, decryptionMaterials()
            .algorithmSuiteId(SIGNING_SUITE)
            .encryptionContext(ec)
            .build(), SIGNING_SUITE, ec);
    }
}
