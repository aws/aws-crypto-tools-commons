package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.InitializeDecryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.InitializeEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.mpl.testserver.client.model.OnDecryptInput;
import aws.cryptography.mpl.testserver.client.model.OnEncryptInput;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Keyring calls that any keyring's tests can use.
 *
 * <p>Each call goes to one language's MPL, through that language's test server.
 * The {@code MPLTestServerClient} argument says which language: get it with
 * {@code MplTestServerClients.forEndpoint(languageServer.endpoint())}.
 */
final class KeyringTestHelpers {

    private KeyringTestHelpers() {
    }

    /** New encryption materials, with no data key yet. */
    static EncryptionMaterials initializeEncryption(MPLTestServerClient mpl, AlgorithmSuiteId suite,
            Map<String, String> encryptionContext) {
        EncryptionMaterials materials = MplTestServerClients.withRetry(() ->
            mpl.initializeEncryptionMaterials(InitializeEncryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(encryptionContext)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new encryption materials hold no data key");
        return materials;
    }

    /** New decryption materials, with no data key yet. */
    static DecryptionMaterials initializeDecryption(MPLTestServerClient mpl, AlgorithmSuiteId suite,
            Map<String, String> encryptionContext) {
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            mpl.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(encryptionContext)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new decryption materials hold no data key");
        return materials;
    }

    /** OnEncrypt, which must succeed and return materials with a data key. */
    static EncryptionMaterials onEncrypt(MPLTestServerClient mpl, String keyringId, EncryptionMaterials materials) {
        EncryptionMaterials out = MplTestServerClients.withRetry(() ->
            mpl.onEncrypt(OnEncryptInput.builder()
                .keyringId(keyringId)
                .materials(materials)
                .build())).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        assertEquals(materials.getAlgorithmSuiteId().getValue(), out.getAlgorithmSuiteId().getValue());
        return out;
    }

    /** OnDecrypt, which must succeed and return materials with a data key. */
    static DecryptionMaterials onDecrypt(MPLTestServerClient mpl, String keyringId, DecryptionMaterials materials,
            List<EncryptedDataKey> encryptedDataKeys) {
        DecryptionMaterials out = MplTestServerClients.withRetry(() ->
            mpl.onDecrypt(OnDecryptInput.builder()
                .keyringId(keyringId)
                .materials(materials)
                .encryptedDataKeys(encryptedDataKeys)
                .build())).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        return out;
    }

    /** Start an OnEncrypt call that must fail. {@link OnEncryptFailure#withError} runs it. */
    static OnEncryptFailure assertOnEncryptFails() {
        return new OnEncryptFailure();
    }

    /** Start an OnDecrypt call that must fail. {@link OnDecryptFailure#withError} runs it. */
    static OnDecryptFailure assertOnDecryptFails() {
        return new OnDecryptFailure();
    }

    static final class OnEncryptFailure {
        private LanguageServerTarget languageServer;
        private String keyringId;
        private EncryptionMaterials materials;

        private OnEncryptFailure() {
        }

        /**
         * The language's MPL that runs the call, such as the Rust MPL or the Java MPL.
         * Each language has its own small server that receives the call over HTTP and passes it to that MPL.
         */
        OnEncryptFailure languageServer(LanguageServerTarget languageServer) {
            this.languageServer = languageServer;
            return this;
        }

        OnEncryptFailure keyringId(String keyringId) {
            this.keyringId = keyringId;
            return this;
        }

        OnEncryptFailure materials(EncryptionMaterials materials) {
            this.materials = materials;
            return this;
        }

        /** Run OnEncrypt. It must fail with {@code expected}. */
        void withError(ExpectedError expected) {
            MPLTestServerClient mpl = MplTestServerClients.forEndpoint(
                Objects.requireNonNull(languageServer, "languageServer").endpoint());
            OnEncryptInput input = OnEncryptInput.builder()
                .keyringId(Objects.requireNonNull(keyringId, "keyringId"))
                .materials(Objects.requireNonNull(materials, "materials"))
                .build();
            MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.onEncrypt(input));
            MplErrors.expectError(languageServer, error).matches(expected);
        }
    }

    static final class OnDecryptFailure {
        private LanguageServerTarget languageServer;
        private String keyringId;
        private DecryptionMaterials materials;
        private List<EncryptedDataKey> encryptedDataKeys;

        private OnDecryptFailure() {
        }

        /**
         * The language's MPL that runs the call, such as the Rust MPL or the Java MPL.
         * Each language has its own small server that receives the call over HTTP and passes it to that MPL.
         */
        OnDecryptFailure languageServer(LanguageServerTarget languageServer) {
            this.languageServer = languageServer;
            return this;
        }

        OnDecryptFailure keyringId(String keyringId) {
            this.keyringId = keyringId;
            return this;
        }

        OnDecryptFailure materials(DecryptionMaterials materials) {
            this.materials = materials;
            return this;
        }

        OnDecryptFailure encryptedDataKeys(List<EncryptedDataKey> encryptedDataKeys) {
            this.encryptedDataKeys = encryptedDataKeys;
            return this;
        }

        /** Run OnDecrypt. It must fail with {@code expected}. */
        void withError(ExpectedError expected) {
            MPLTestServerClient mpl = MplTestServerClients.forEndpoint(
                Objects.requireNonNull(languageServer, "languageServer").endpoint());
            OnDecryptInput input = OnDecryptInput.builder()
                .keyringId(Objects.requireNonNull(keyringId, "keyringId"))
                .materials(Objects.requireNonNull(materials, "materials"))
                .encryptedDataKeys(Objects.requireNonNull(encryptedDataKeys, "encryptedDataKeys"))
                .build();
            MPLClientError error = assertThrows(MPLClientError.class, () -> mpl.onDecrypt(input));
            MplErrors.expectError(languageServer, error).matches(expected);
        }
    }

    /** {@code length} bytes that are the same on every run. Each {@code seed} gives different bytes. */
    static byte[] bytes(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 7 + seed * 31 + 1);
        }
        return out;
    }

    /** Copy a ByteBuffer's remaining bytes without moving its position. */
    static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }
}
