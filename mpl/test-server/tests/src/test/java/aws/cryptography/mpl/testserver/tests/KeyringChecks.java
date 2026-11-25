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
 * Checks every keyring must pass.
 * Each keyring's test file calls them from its own tests, with its own spec annotation.
 *
 * <p>The rules come from keyring-interface.md.
 * Each check takes the {@link Mpl} that created {@code keyring}, and makes new materials with it.
 * A keyring that calls a service, such as KMS, must be set up to answer every call that a check makes.
 */
final class KeyringChecks {

    private KeyringChecks() {
    }

    /** OnDecrypt gets back the data key that OnEncrypt made. */
    static void encryptsAndDecrypts(Mpl mpl, Keyring keyring) {
        keyring.assertEncryptsAndDecrypts();
    }

    /**
     * OnEncrypt on materials that already hold a data key keeps that data key and adds at least one EDK.
     * The first OnEncrypt makes the data key, so it has the length that the algorithm suite needs.
     */
    static void keepsAnExistingDataKeyOnEncrypt(Mpl mpl, Keyring keyring) {
        EncryptionMaterials withDataKey = keyring.onEncrypt(mpl.newEncryptionMaterials());
        EncryptionMaterials encrypted = keyring.onEncrypt(withDataKey);

        assertArrayEquals(bytes(withDataKey.getPlaintextDataKey()), bytes(encrypted.getPlaintextDataKey()),
            "OnEncrypt must not replace a data key that the materials already hold");
        assertTrue(encrypted.getEncryptedDataKeys().size() > withDataKey.getEncryptedDataKeys().size(),
            "OnEncrypt must add an EDK for the existing data key");
    }

    /**
     * OnDecrypt fails on materials that already hold a data key.
     * The EDKs come from this keyring, and OnDecrypt first succeeds with them on new materials.
     * So the failure can only come from the data key in the materials.
     */
    static void rejectsDecryptionMaterialsThatHaveADataKey(Mpl mpl, Keyring keyring) {
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());
        List<EncryptedDataKey> edks = encrypted.getEncryptedDataKeys();
        keyring.onDecrypt(mpl.newDecryptionMaterials(), edks);

        DecryptionMaterials withDataKey =
            materialsWithDataKey(mpl.newDecryptionMaterials(), bytes(encrypted.getPlaintextDataKey()));
        keyring.onDecryptFailsWith(withDataKey, edks, INVALID_MATERIALS_ERROR);
    }

    /**
     * OnDecrypt fails when none of {@code otherEdks} is for this keyring.
     * Only the caller knows which EDKs another keyring would write, so the caller passes them.
     * OnDecrypt first succeeds with this keyring's own EDKs, which shows the keyring can decrypt at all.
     */
    static void failsWhenNoEdkMatches(Mpl mpl, Keyring keyring, List<EncryptedDataKey> otherEdks) {
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());
        keyring.onDecrypt(mpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        keyring.onDecryptFailsWith(mpl.newDecryptionMaterials(), otherEdks, NO_MATCHING_DATA_KEY_ERROR);
    }
}
