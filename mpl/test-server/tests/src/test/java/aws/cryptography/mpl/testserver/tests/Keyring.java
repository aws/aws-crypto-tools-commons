package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.mpl.testserver.client.model.OnDecryptInput;
import aws.cryptography.mpl.testserver.client.model.OnEncryptInput;
import aws.cryptography.testserver.tests.ExpectedError;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * A keyring that a language's MPL created.
 *
 * <p>The keyring lives in that language's test server.
 * This object holds only the ID that the test server gave it, and sends each call to the same {@link Mpl}.
 */
final class Keyring {

    private final Mpl mpl;
    private final String keyringId;

    Keyring(Mpl mpl, String keyringId) {
        this.mpl = mpl;
        this.keyringId = keyringId;
    }

    /** The ID that the test server gave this keyring. */
    String id() {
        return keyringId;
    }

    /** OnEncrypt, which must succeed and return materials with a data key and the same suite. */
    EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        EncryptionMaterials out = MplTestServerClients.withRetry(() ->
            mpl.testServer().onEncrypt(onEncryptInput(materials))).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        assertEquals(materials.getAlgorithmSuiteId().getValue(), out.getAlgorithmSuiteId().getValue());
        return out;
    }

    /** OnDecrypt, which must succeed and return materials with a data key. */
    DecryptionMaterials onDecrypt(DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        DecryptionMaterials out = MplTestServerClients.withRetry(() ->
            mpl.testServer().onDecrypt(onDecryptInput(materials, encryptedDataKeys))).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        return out;
    }

    /** OnEncrypt, which must fail with {@code expected}. */
    MPLClientError onEncryptFailsWith(EncryptionMaterials materials, ExpectedError expected) {
        OnEncryptInput input = onEncryptInput(materials);
        MPLClientError error = assertThrows(MPLClientError.class, () ->
            MplTestServerClients.withRetry(() -> mpl.testServer().onEncrypt(input)));
        MplErrors.expectError(mpl.languageServer(), error).matches(expected);
        return error;
    }

    /** OnDecrypt, which must fail with {@code expected}. */
    MPLClientError onDecryptFailsWith(DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys,
            ExpectedError expected) {
        OnDecryptInput input = onDecryptInput(materials, encryptedDataKeys);
        MPLClientError error = assertThrows(MPLClientError.class, () ->
            MplTestServerClients.withRetry(() -> mpl.testServer().onDecrypt(input)));
        MplErrors.expectError(mpl.languageServer(), error).matches(expected);
        return error;
    }

    /**
     * Check that the keyring works, not just that it was created.
     * OnEncrypt on new materials must make a data key and an encrypted data key (EDK).
     * OnDecrypt must then get the same data key back from that EDK.
     */
    void assertEncryptsAndDecrypts() {
        EncryptionMaterials encryptionMaterials = mpl.newEncryptionMaterials();
        DecryptionMaterials decryptionMaterials = mpl.newDecryptionMaterials();
        EncryptionMaterials encrypted = onEncrypt(encryptionMaterials);
        DecryptionMaterials decrypted = onDecrypt(decryptionMaterials, encrypted.getEncryptedDataKeys());
        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()),
            "OnDecrypt must return the data key that OnEncrypt made");
    }

    private OnEncryptInput onEncryptInput(EncryptionMaterials materials) {
        return OnEncryptInput.builder()
            .keyringId(keyringId)
            .materials(materials)
            .build();
    }

    private OnDecryptInput onDecryptInput(DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        return OnDecryptInput.builder()
            .keyringId(keyringId)
            .materials(materials)
            .encryptedDataKeys(encryptedDataKeys)
            .build();
    }

    /** Copy a ByteBuffer's remaining bytes without moving its position. */
    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }
}
