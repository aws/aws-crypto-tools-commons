package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertNull;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.InitializeDecryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.InitializeEncryptionMaterialsInput;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Materials, encrypted data keys (EDKs) and byte arrays that keyring and CMM tests pass to the MPL.
 *
 * <p>A test gets new materials from {@link Mpl#newEncryptionMaterials()}, which calls this class.
 */
final class Materials {

    private Materials() {
    }

    /** New encryption materials from {@code testServer}'s MPL, with no data key yet. */
    static EncryptionMaterials newEncryptionMaterials(MPLTestServerClient testServer, AlgorithmSuiteId suite,
            Map<String, String> encryptionContext) {
        EncryptionMaterials materials = MplTestServerClients.withRetry(() ->
            testServer.initializeEncryptionMaterials(InitializeEncryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(encryptionContext)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new encryption materials hold no data key");
        return materials;
    }

    /** New decryption materials from {@code testServer}'s MPL, with no data key yet. */
    static DecryptionMaterials newDecryptionMaterials(MPLTestServerClient testServer, AlgorithmSuiteId suite,
            Map<String, String> encryptionContext) {
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            testServer.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(encryptionContext)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new decryption materials hold no data key");
        return materials;
    }

    /** {@code materials} with {@code dataKey} as their plaintext data key. */
    static EncryptionMaterials materialsWithDataKey(EncryptionMaterials materials, byte[] dataKey) {
        return materials.toBuilder()
            .plaintextDataKey(ByteBuffer.wrap(dataKey))
            .build();
    }

    /**
     * An EDK for {@code providerId} and {@code providerInfo}.
     * Each {@code seed} gives a different ciphertext, so a test can tell EDKs apart.
     */
    static EncryptedDataKey edk(String providerId, String providerInfo, int seed) {
        return EncryptedDataKey.builder()
            .keyProviderId(providerId)
            .keyProviderInfo(ByteBuffer.wrap(providerInfo.getBytes(StandardCharsets.UTF_8)))
            .ciphertext(ByteBuffer.wrap(bytes(64, seed)))
            .build();
    }

    /** {@code edk} with {@code providerInfo} in place of its own. */
    static EncryptedDataKey withProviderInfo(EncryptedDataKey edk, byte[] providerInfo) {
        return edk.toBuilder().keyProviderInfo(ByteBuffer.wrap(providerInfo)).build();
    }

    /** {@code length} bytes that are the same on every run. Each {@code seed} gives different bytes. */
    static byte[] bytes(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 7 + seed * 31 + 1);
        }
        return out;
    }

    /** A data key of {@code length} bytes, for a test that chooses the data key's length. */
    static byte[] dataKeyOfLength(int length) {
        return bytes(length, 1);
    }

    /** Copy a ByteBuffer's remaining bytes without moving its position. */
    static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }
}
