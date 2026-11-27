package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static aws.cryptography.mpl.testserver.tests.Materials.materialsWithDataKey;
import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_MATERIALS_ERROR;
import static aws.cryptography.mpl.testserver.tests.MplErrors.NO_MATCHING_DATA_KEY_ERROR;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import java.util.List;

/**
 * Tests that every keyring must pass, from the rules in keyring-interface.md.
 *
 * <p>Every keyring test class implements this interface, so every keyring runs these tests.
 * The class puts {@link KeyringFeature} on itself, and each test here runs with that feature.
 * The annotations here cite only keyring-interface.md, because those rules apply to every keyring.
 * A keyring whose own spec repeats a rule overrides that one test, only to add the annotation from its own spec.
 * The override calls the test here, such as {@code KeyringContract.super.encryptsAndDecrypts(mpl)}.
 * A keyring that does not follow a rule overrides that test with an empty body and {@link ContractException}, which skips it.
 *
 * <p>Each test makes new materials with the {@link Mpl} that it gets.
 * A keyring that calls a service, such as KMS, must answer every call that a test here makes.
 */
interface KeyringContract {

    /** A keyring that encrypts and decrypts, made with {@code mpl}. */
    Keyring workingKeyring(Mpl mpl);

    /**
     * EDKs that the keyring from {@link #workingKeyring} cannot decrypt, such as EDKs for another provider or key.
     * Only the keyring's own test class knows which EDKs another keyring would write.
     */
    List<EncryptedDataKey> edksThatDontMatch();

    /** OnDecrypt gets back the data key that OnEncrypt made. */
    @KeyringTest
    default void encryptsAndDecrypts(Mpl mpl) {
        //= spec/framework/keyring-interface.md#encrypt-data-key
        //= type=test
        //# The [encrypted data keys](structures.md#encrypted-data-key) produced by this keyring MUST
        //# have [ciphertexts](structures.md#ciphertext) that can be decrypted to the plaintext data key in the
        //# [encryption materials](structures.md#encryption-materials).
        workingKeyring(mpl).assertEncryptsAndDecrypts();
    }

    /**
     * OnEncrypt on materials that already hold a data key keeps that data key and adds at least one EDK.
     * The first OnEncrypt makes the data key, so it has the length that the algorithm suite needs.
     */
    @KeyringTest
    default void keepsAnExistingDataKeyOnEncrypt(Mpl mpl) {
        Keyring keyring = workingKeyring(mpl);
        EncryptionMaterials withDataKey = keyring.onEncrypt(mpl.newEncryptionMaterials());
        EncryptionMaterials encrypted = keyring.onEncrypt(withDataKey);

        //= spec/framework/keyring-interface.md#generate-data-key
        //= type=test
        //# If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.
        assertArrayEquals(bytes(withDataKey.getPlaintextDataKey()), bytes(encrypted.getPlaintextDataKey()),
            "OnEncrypt must not replace a data key that the materials already hold");

        //= spec/framework/keyring-interface.md#encrypt-data-key
        //= type=test
        //# If the [encryption materials](structures.md#encryption-materials) contain a plaintext data key,
        //# OnEncrypt MUST encrypt a data key.
        assertTrue(encrypted.getEncryptedDataKeys().size() > withDataKey.getEncryptedDataKeys().size(),
            "OnEncrypt must add an EDK for the existing data key");
    }

    /**
     * OnDecrypt fails on materials that already hold a data key.
     * The EDKs come from this keyring, and OnDecrypt first succeeds with them on new materials.
     * So the failure can only come from the data key in the materials.
     */
    @KeyringTest
    default void rejectsDecryptionMaterialsThatHaveADataKey(Mpl mpl) {
        Keyring keyring = workingKeyring(mpl);
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());
        List<EncryptedDataKey> edks = encrypted.getEncryptedDataKeys();
        keyring.onDecrypt(mpl.newDecryptionMaterials(), edks);

        DecryptionMaterials withDataKey =
            materialsWithDataKey(mpl.newDecryptionMaterials(), bytes(encrypted.getPlaintextDataKey()));
        //= spec/framework/keyring-interface.md#ondecrypt
        //= type=test
        //# If the decryption materials already contain a plaintext data key,
        //# the keyring MUST fail
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        keyring.onDecryptFailsWith(withDataKey, edks, INVALID_MATERIALS_ERROR);
    }

    /**
     * OnDecrypt fails when none of the {@link #edksThatDontMatch} EDKs is for this keyring.
     * OnDecrypt first succeeds with this keyring's own EDKs, which shows the keyring can decrypt at all.
     */
    @KeyringTest
    default void failsWhenNoEdkMatches(Mpl mpl) {
        Keyring keyring = workingKeyring(mpl);
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());
        keyring.onDecrypt(mpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        //= spec/framework/keyring-interface.md#decrypt-data-key
        //= type=test
        //# If the keyring is unable to get any plaintext data key using the input [encrypted data keys](structures.md#encrypted-data-key),
        //# the keyring MUST NOT not update the [decryption materials](structures.md#decryption-materials) and MUST return failure.
        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), edksThatDontMatch(), NO_MATCHING_DATA_KEY_ERROR);
    }
}
