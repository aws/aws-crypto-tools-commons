package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.Cmm.PUBLIC_KEY_EC_KEY;
import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
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
@KeyringFeature({"static-keyring", "default-cmm"})
public class MaterialsChecksTest {

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

    /** A Default CMM over a static keyring that returns {@code encryption} and {@code decryption}. */
    private static Cmm cmm(Mpl mpl, EncryptionMaterials encryption, DecryptionMaterials decryption) {
        return mpl.defaultCmm(mpl.staticKeyring(encryption, decryption));
    }

    private static DecryptMaterialsInput.Builder decryptMaterials(Cmm cmm, AlgorithmSuiteId suite,
            Map<String, String> ec) {
        return cmm.decryptMaterialsRequest()
            .algorithmSuiteId(suite)
            .encryptedDataKeys(List.of(edk()))
            .encryptionContext(ec)
            .commitmentPolicy(POLICY);
    }

    /** GetEncryptionMaterials fails on a Default CMM whose keyring returns {@code materials} from OnEncrypt. */
    private static void assertEncryptRejected(Mpl mpl, EncryptionMaterials materials) {
        cmm(mpl, materials, null).getEncryptionMaterialsFails(EC, POLICY, SUITE);
    }

    /** DecryptMaterials fails on a Default CMM whose keyring returns {@code materials} from OnDecrypt. */
    private static void assertDecryptRejected(Mpl mpl, DecryptionMaterials materials,
            AlgorithmSuiteId suite, Map<String, String> ec) {
        Cmm cmm = cmm(mpl, null, materials);
        cmm.decryptMaterialsFails(decryptMaterials(cmm, suite, ec));
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

    @KeyringTest(name = "[materials-checks] encrypt accepts an added data key {0}")
    void encryptAcceptsAddedDataKey(Mpl mpl) {
        Cmm cmm = cmm(mpl, encryptionMaterials().build(), null);

        GetEncryptionMaterialsOutput out = cmm.getEncryptionMaterials(EC, POLICY, SUITE);

        assertArrayEquals(DATA_KEY, bytes(out.getPlaintextDataKey()));
        assertEquals(1, out.getEncryptedDataKeys().size());
        assertEquals("static", out.getEncryptedDataKeys().get(0).getKeyProviderId());
    }

    @KeyringTest(name = "[materials-checks] encrypt rejects no data key {0}")
    void encryptRejectsNoDataKey(Mpl mpl) {
        cmm(mpl, null, null).getEncryptionMaterialsFails(EC, POLICY, SUITE);
    }

    @KeyringTest(name = "[materials-checks] encrypt rejects no encrypted data keys {0}")
    void encryptRejectsNoEncryptedDataKeys(Mpl mpl) {
        assertEncryptRejected(mpl, encryptionMaterials().encryptedDataKeys(List.of()).build());
    }

    @KeyringTest(name = "[materials-checks] encrypt rejects a changed algorithm suite {0}")
    void encryptRejectsChangedSuite(Mpl mpl) {
        assertEncryptRejected(mpl, encryptionMaterials().algorithmSuiteId(OTHER_SUITE).build());
    }

    @KeyringTest(name = "[materials-checks] encrypt rejects a changed encryption context {0}")
    void encryptRejectsChangedContext(Mpl mpl) {
        assertEncryptRejected(mpl,
            encryptionMaterials().encryptionContext(with(EC, "added", "by keyring")).build());
    }

    @KeyringTest(name = "[materials-checks] encrypt rejects changed required context keys {0}")
    void encryptRejectsChangedRequiredKeys(Mpl mpl) {
        assertEncryptRejected(mpl,
            encryptionMaterials().requiredEncryptionContextKeys(List.of("purpose")).build());
    }

    // -----------------------------------------------------------------------
    // DecryptMaterials
    // -----------------------------------------------------------------------

    @KeyringTest(name = "[materials-checks] decrypt accepts an added data key {0}")
    void decryptAcceptsAddedDataKey(Mpl mpl) {
        Cmm cmm = cmm(mpl, null, decryptionMaterials().build());

        DecryptMaterialsOutput out = cmm.decryptMaterials(decryptMaterials(cmm, SUITE, EC));

        assertArrayEquals(DATA_KEY, bytes(out.getPlaintextDataKey()));
    }

    @KeyringTest(name = "[materials-checks] decrypt rejects no data key {0}")
    void decryptRejectsNoDataKey(Mpl mpl) {
        Cmm cmm = cmm(mpl, null, null);
        cmm.decryptMaterialsFails(decryptMaterials(cmm, SUITE, EC));
    }

    @KeyringTest(name = "[materials-checks] decrypt rejects a changed algorithm suite {0}")
    void decryptRejectsChangedSuite(Mpl mpl) {
        assertDecryptRejected(mpl, decryptionMaterials().algorithmSuiteId(OTHER_SUITE).build(), SUITE, EC);
    }

    @KeyringTest(name = "[materials-checks] decrypt rejects a changed encryption context {0}")
    void decryptRejectsChangedContext(Mpl mpl) {
        assertDecryptRejected(mpl,
            decryptionMaterials().encryptionContext(with(EC, "added", "by keyring")).build(), SUITE, EC);
    }

    @KeyringTest(name = "[materials-checks] decrypt rejects changed required context keys {0}")
    void decryptRejectsChangedRequiredKeys(Mpl mpl) {
        assertDecryptRejected(mpl,
            decryptionMaterials().requiredEncryptionContextKeys(List.of("purpose")).build(), SUITE, EC);
    }

    @KeyringTest(name = "[materials-checks] decrypt accepts a data key for a signing suite {0}")
    void decryptAcceptsSigningSuiteDataKey(Mpl mpl) throws GeneralSecurityException {
        byte[] verificationKey = verificationKey();
        Map<String, String> ec = with(EC, PUBLIC_KEY_EC_KEY, Base64.getEncoder().encodeToString(verificationKey));
        Cmm cmm = cmm(mpl, null, decryptionMaterials()
            .algorithmSuiteId(SIGNING_SUITE)
            .encryptionContext(ec)
            .verificationKey(ByteBuffer.wrap(verificationKey))
            .build());

        DecryptMaterialsOutput out = cmm.decryptMaterials(decryptMaterials(cmm, SIGNING_SUITE, ec));

        assertArrayEquals(DATA_KEY, bytes(out.getPlaintextDataKey()));
        assertArrayEquals(verificationKey, bytes(out.getVerificationKey()));
    }

    @KeyringTest(name = "[materials-checks] decrypt rejects a changed verification key {0}")
    void decryptRejectsChangedVerificationKey(Mpl mpl) throws GeneralSecurityException {
        byte[] verificationKey = verificationKey();
        Map<String, String> ec = with(EC, PUBLIC_KEY_EC_KEY, Base64.getEncoder().encodeToString(verificationKey));
        assertDecryptRejected(mpl, decryptionMaterials()
            .algorithmSuiteId(SIGNING_SUITE)
            .encryptionContext(ec)
            .verificationKey(ByteBuffer.wrap(verificationKey()))
            .build(), SIGNING_SUITE, ec);
    }

    @KeyringTest(name = "[materials-checks] decrypt rejects a signing suite with no verification key {0}")
    void decryptRejectsMissingVerificationKey(Mpl mpl) throws GeneralSecurityException {
        Map<String, String> ec = with(EC, PUBLIC_KEY_EC_KEY, Base64.getEncoder().encodeToString(verificationKey()));
        assertDecryptRejected(mpl, decryptionMaterials()
            .algorithmSuiteId(SIGNING_SUITE)
            .encryptionContext(ec)
            .build(), SIGNING_SUITE, ec);
    }
}
