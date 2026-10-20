package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
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
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The Raw AES keyring driven directly through the keyring interface, across the
 * pairwise matrix: OnEncrypt on the encrypt target, OnDecrypt on the decrypt
 * target with the encrypted data keys the encrypt target produced.
 *
 * <p>The encrypt side's EDK is also checked byte-for-byte against the Raw AES
 * keyring's serialization (key provider id = key namespace; key provider info =
 * key name || tag length in bits (u32) || IV length (u32) || IV; ciphertext =
 * wrapped key || 16-byte tag), so two implementations that agree only with
 * themselves still fail here.
 */
public class RawAesKeyringTest {

    private static final String NAMESPACE = "mpl-test-server";
    private static final String KEY_NAME = "raw-aes-keyring-key";

    /** A non-signing, committing suite: its materials carry no signing key. */
    private static final AlgorithmSuiteId SUITE =
        AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final int SUITE_DATA_KEY_LENGTH = 32;

    private static final Map<String, String> EC = Map.of("purpose", "raw-aes-keyring-test");

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    static Stream<Arguments> pairsByWrappingAlg() {
        List<TargetPair> pairs = LanguageServerRegistry.shared().pairs();
        return AesWrappingAlg.values().stream()
            .flatMap(alg -> pairs.stream().map(pair -> Arguments.of(alg, pair)));
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    @ParameterizedTest(name = "[raw-aes] {0} OnEncrypt/OnDecrypt {1}")
    @MethodSource("pairsByWrappingAlg")
    void onEncryptOnDecryptRoundTrip(AesWrappingAlg alg, TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        MPLTestServerClient enc = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        byte[] wrappingKey = wrappingKey(alg, 0);

        EncryptionMaterials encrypted = onEncrypt(enc,
            createKeyring(enc, KEY_NAME, wrappingKey, alg), initializeEncryption(enc));

        byte[] plaintextDataKey = bytes(encrypted.getPlaintextDataKey());
        assertEquals(SUITE_DATA_KEY_LENGTH, plaintextDataKey.length);
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertRawAesEdk(encrypted.getEncryptedDataKeys().get(0), KEY_NAME);

        DecryptionMaterials decrypted = onDecrypt(dec,
            createKeyring(dec, KEY_NAME, wrappingKey, alg),
            initializeDecryption(dec), encrypted.getEncryptedDataKeys());

        assertArrayEquals(plaintextDataKey, bytes(decrypted.getPlaintextDataKey()));
    }

    /**
     * A second OnEncrypt over materials that already hold a data key must wrap
     * that same key and append its EDK, not generate a new key. The decrypt
     * target then unwraps with only the second keyring, from the full EDK list.
     */
    @ParameterizedTest(name = "[raw-aes] wrap existing data key {0}")
    @MethodSource("pairs")
    void onEncryptWrapsExistingDataKey(TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        MPLTestServerClient enc = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] firstKey = wrappingKey(alg, 0);
        byte[] secondKey = wrappingKey(alg, 1);

        EncryptionMaterials first = onEncrypt(enc,
            createKeyring(enc, "first-key", firstKey, alg), initializeEncryption(enc));
        EncryptionMaterials second = onEncrypt(enc,
            createKeyring(enc, "second-key", secondKey, alg), first);

        assertArrayEquals(bytes(first.getPlaintextDataKey()), bytes(second.getPlaintextDataKey()),
            "wrapping an existing data key must not replace it");
        assertEquals(2, second.getEncryptedDataKeys().size());
        assertRawAesEdk(second.getEncryptedDataKeys().get(0), "first-key");
        assertRawAesEdk(second.getEncryptedDataKeys().get(1), "second-key");

        DecryptionMaterials decrypted = onDecrypt(dec,
            createKeyring(dec, "second-key", secondKey, alg),
            initializeDecryption(dec), second.getEncryptedDataKeys());

        assertArrayEquals(bytes(first.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    @ParameterizedTest(name = "[raw-aes] wrong wrapping key rejected {0}")
    @MethodSource("pairs")
    void onDecryptWithWrongWrappingKeyFails(TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        MPLTestServerClient enc = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;

        EncryptionMaterials encrypted = onEncrypt(enc,
            createKeyring(enc, KEY_NAME, wrappingKey(alg, 0), alg), initializeEncryption(enc));

        // Same namespace and name, so the EDK is a candidate; the unwrap itself must fail.
        String wrongKeyring = createKeyring(dec, KEY_NAME, wrappingKey(alg, 1), alg);
        DecryptionMaterials initial = initializeDecryption(dec);
        assertThrows(MPLClientError.class, () -> dec.onDecrypt(OnDecryptInput.builder()
            .keyringId(wrongKeyring)
            .materials(initial)
            .encryptedDataKeys(encrypted.getEncryptedDataKeys())
            .build()));
    }

    @ParameterizedTest(name = "[raw-aes] non-matching key name rejected {0}")
    @MethodSource("pairs")
    void onDecryptWithNonMatchingKeyNameFails(TargetPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        MPLTestServerClient enc = MplTestServerClients.forEndpoint(pair.encryptEndpoint());
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] wrappingKey = wrappingKey(alg, 0);

        EncryptionMaterials encrypted = onEncrypt(enc,
            createKeyring(enc, KEY_NAME, wrappingKey, alg), initializeEncryption(enc));

        // Same wrapping key under another name: the keyring must not attempt the EDK.
        String otherName = createKeyring(dec, "some-other-key-name", wrappingKey, alg);
        DecryptionMaterials initial = initializeDecryption(dec);
        assertThrows(MPLClientError.class, () -> dec.onDecrypt(OnDecryptInput.builder()
            .keyringId(otherName)
            .materials(initial)
            .encryptedDataKeys(encrypted.getEncryptedDataKeys())
            .build()));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static void assertRawAesEdk(EncryptedDataKey edk, String keyName) {
        assertEquals(NAMESPACE, edk.getKeyProviderId(), "key provider id is the key namespace");

        byte[] name = keyName.getBytes(StandardCharsets.UTF_8);
        byte[] info = bytes(edk.getKeyProviderInfo());
        assertEquals(name.length + 4 + 4 + IV_LENGTH, info.length, "key provider info length");
        assertArrayEquals(name, Arrays.copyOfRange(info, 0, name.length), "key name prefix");
        ByteBuffer fields = ByteBuffer.wrap(info, name.length, 8);
        assertEquals(TAG_LENGTH * 8, fields.getInt(), "tag length in bits");
        assertEquals(IV_LENGTH, fields.getInt(), "IV length");

        assertEquals(SUITE_DATA_KEY_LENGTH + TAG_LENGTH, bytes(edk.getCiphertext()).length,
            "ciphertext is the wrapped data key followed by the GCM tag");
    }

    private static String createKeyring(
        MPLTestServerClient client, String keyName, byte[] wrappingKey, AesWrappingAlg alg) {
        return MplTestServerClients.withRetry(() -> client.createRawAesKeyring(
            CreateRawAesKeyringInput.builder()
                .keyNamespace(NAMESPACE)
                .keyName(keyName)
                .wrappingKey(ByteBuffer.wrap(wrappingKey))
                .wrappingAlg(alg)
                .build())).getKeyringId();
    }

    private static EncryptionMaterials initializeEncryption(MPLTestServerClient client) {
        EncryptionMaterials materials = MplTestServerClients.withRetry(() ->
            client.initializeEncryptionMaterials(InitializeEncryptionMaterialsInput.builder()
                .algorithmSuiteId(SUITE)
                .encryptionContext(EC)
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertEquals(SUITE.getValue(), materials.getAlgorithmSuiteId().getValue());
        assertNull(materials.getPlaintextDataKey(), "initialized materials carry no data key");
        assertEquals(0, materials.getEncryptedDataKeys().size());
        return materials;
    }

    private static DecryptionMaterials initializeDecryption(MPLTestServerClient client) {
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            client.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(SUITE)
                .encryptionContext(EC)
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
        assertEquals(SUITE.getValue(), out.getAlgorithmSuiteId().getValue());
        assertEquals(EC, out.getEncryptionContext());
        return out;
    }

    private static DecryptionMaterials onDecrypt(
        MPLTestServerClient client, String keyringId, DecryptionMaterials materials,
        List<EncryptedDataKey> edks) {
        DecryptionMaterials out = MplTestServerClients.withRetry(() ->
            client.onDecrypt(OnDecryptInput.builder()
                .keyringId(keyringId)
                .materials(materials)
                .encryptedDataKeys(edks)
                .build())).getMaterials();
        assertNotNull(out.getPlaintextDataKey());
        return out;
    }

    /** A deterministic wrapping key of the length {@code alg} requires; {@code seed} varies it. */
    private static byte[] wrappingKey(AesWrappingAlg alg, int seed) {
        int length;
        if (alg.equals(AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16)) {
            length = 16;
        } else if (alg.equals(AesWrappingAlg.ALG_AES192_GCM_IV12_TAG16)) {
            length = 24;
        } else if (alg.equals(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)) {
            length = 32;
        } else {
            throw new IllegalArgumentException("unknown wrapping algorithm " + alg.getValue());
        }
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            key[i] = (byte) (i + seed * 101);
        }
        return key;
    }

    /** Copy a ByteBuffer's remaining bytes without moving its position. */
    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }
}
