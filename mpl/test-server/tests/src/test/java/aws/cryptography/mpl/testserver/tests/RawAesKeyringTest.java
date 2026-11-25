package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static aws.cryptography.mpl.testserver.tests.Materials.edk;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.RawAesWrappingKeys;
import aws.cryptography.testserver.tests.RawAesWrappingKeys.WrappingKey;
import aws.cryptography.testserver.tests.RawKeyringNames;
import aws.cryptography.testserver.tests.RawKeyringNames.KeyNames;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
@KeyringFeature("raw-aes")
public class RawAesKeyringTest implements KeyringTestDefaults, KeyringContract {

    private static final String NAMESPACE = "mpl-test-server";
    private static final String KEY_NAME = "raw-aes-keyring-key";

    /** A non-signing, committing suite: its materials carry no signing key. */
    private static final AlgorithmSuiteId SUITE =
        AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final int SUITE_DATA_KEY_LENGTH = 32;

    private static final Map<String, String> EC = Map.of("purpose", "raw-aes-keyring-test");

    /** One value of 2^16 bytes: one more than the u16 value length allows. */
    private static final Map<String, String> UNSERIALIZABLE_EC = Map.of("keyA", "a".repeat(0x1_0000));

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    @Override
    public AlgorithmSuiteId algorithmSuite() {
        return SUITE;
    }

    @Override
    public Map<String, String> encryptionContext() {
        return EC;
    }

    static List<Example<WrappingKey>> validWrappingKeys() {
        return RawAesWrappingKeys.validWrappingKeys();
    }

    static List<Example<WrappingKey>> invalidWrappingKeys() {
        return RawAesWrappingKeys.invalidWrappingKeys();
    }

    static List<Example<KeyNames>> validKeyNames() {
        return RawKeyringNames.validKeyNames();
    }

    static List<Example<KeyNames>> invalidKeyNames() {
        return RawKeyringNames.invalidKeyNames();
    }

    @KeyringTest(
        name = "[raw-aes] {0} OnEncrypt/OnDecrypt {1}",
        inputs = "validWrappingKeys",
        pairs = true)
    void onEncryptOnDecryptRoundTrip(Example<WrappingKey> example, Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = wrappingAlg(example.value().algorithmKeyLength());
        byte[] wrappingKey = example.value().key();

        EncryptionMaterials encrypted = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg),
            newEncryptionMaterials(encryptingMpl, EC));

        byte[] plaintextDataKey = bytes(encrypted.getPlaintextDataKey());
        assertEquals(SUITE_DATA_KEY_LENGTH, plaintextDataKey.length);
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertRawAesEdk(encrypted.getEncryptedDataKeys().get(0), NAMESPACE, KEY_NAME);

        DecryptionMaterials decrypted = rawAesKeyring(decryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(plaintextDataKey, bytes(decrypted.getPlaintextDataKey()));
    }

    @KeyringTest(
        name = "[raw-aes] wrong wrapping key length rejected {0} {1}",
        inputs = "invalidWrappingKeys")
    void createRejectsWrongWrappingKeyLength(Example<WrappingKey> example, Mpl mpl) {
        mpl.rawAesKeyring()
            .keyNamespace(NAMESPACE)
            .keyName(KEY_NAME)
            .wrappingKey(example.value().key())
            .wrappingAlg(wrappingAlg(example.value().algorithmKeyLength()))
            .createFails();
    }

    /**
     * The encrypt target writes the key namespace and key name into the EDK as UTF-8,
     * and the decrypt target must match those exact bytes to find its key.
     */
    @KeyringTest(
        name = "[raw-aes] key namespace and name round-trip {0} {1}",
        inputs = "validKeyNames",
        pairs = true)
    void keyNamespaceAndNameRoundTrip(Example<KeyNames> example, Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] wrappingKey = wrappingKey(alg, 0);
        KeyNames names = example.value();

        EncryptionMaterials encrypted = onEncrypt(
            rawAesKeyring(encryptingMpl, names.keyNamespace(), names.keyName(), wrappingKey, alg),
            newEncryptionMaterials(encryptingMpl, EC));
        assertRawAesEdk(encrypted.getEncryptedDataKeys().get(0), names.keyNamespace(), names.keyName());

        DecryptionMaterials decrypted =
            rawAesKeyring(decryptingMpl, names.keyNamespace(), names.keyName(), wrappingKey, alg)
                .onDecrypt(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    @KeyringTest(
        name = "[raw-aes] reserved key namespace rejected {0} {1}",
        inputs = "invalidKeyNames")
    void createRejectsReservedKeyNamespace(Example<KeyNames> example, Mpl mpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        mpl.rawAesKeyring()
            .keyNamespace(example.value().keyNamespace())
            .keyName(example.value().keyName())
            .wrappingKey(wrappingKey(alg, 0))
            .wrappingAlg(alg)
            .createFails();
    }

    /**
     * A second OnEncrypt over materials that already hold a data key must wrap
     * that same key and append its EDK, not generate a new key. The decrypt
     * target then unwraps with only the second keyring, from the full EDK list.
     */
    @KeyringTest(name = "[raw-aes] wrap existing data key {0}", pairs = true)
    void onEncryptWrapsExistingDataKey(Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] firstKey = wrappingKey(alg, 0);
        byte[] secondKey = wrappingKey(alg, 1);

        EncryptionMaterials first = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, "first-key", firstKey, alg),
            newEncryptionMaterials(encryptingMpl, EC));
        EncryptionMaterials second = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, "second-key", secondKey, alg),
            first);

        assertArrayEquals(bytes(first.getPlaintextDataKey()), bytes(second.getPlaintextDataKey()),
            "wrapping an existing data key must not replace it");
        assertEquals(2, second.getEncryptedDataKeys().size());
        assertRawAesEdk(second.getEncryptedDataKeys().get(0), NAMESPACE, "first-key");
        assertRawAesEdk(second.getEncryptedDataKeys().get(1), NAMESPACE, "second-key");

        DecryptionMaterials decrypted = rawAesKeyring(decryptingMpl, NAMESPACE, "second-key", secondKey, alg)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(), second.getEncryptedDataKeys());

        assertArrayEquals(bytes(first.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    @KeyringTest(name = "[raw-aes] wrong wrapping key rejected {0}", pairs = true)
    void onDecryptWithWrongWrappingKeyFails(Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;

        EncryptionMaterials encrypted = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, KEY_NAME, wrappingKey(alg, 0), alg),
            newEncryptionMaterials(encryptingMpl, EC));

        // Same namespace and name, so the EDK is a candidate; the unwrap itself must fail.
        Keyring wrongKeyring = rawAesKeyring(decryptingMpl, NAMESPACE, KEY_NAME, wrappingKey(alg, 1), alg);
        wrongKeyring.onDecryptFails(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());
    }

    @KeyringTest(name = "[raw-aes] non-matching key name rejected {0}", pairs = true)
    void onDecryptWithNonMatchingKeyNameFails(Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] wrappingKey = wrappingKey(alg, 0);

        EncryptionMaterials encrypted = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg),
            newEncryptionMaterials(encryptingMpl, EC));

        // Same wrapping key under another name: the keyring must not attempt the EDK.
        Keyring otherName = rawAesKeyring(decryptingMpl, NAMESPACE, "some-other-key-name", wrappingKey, alg);
        otherName.onDecryptFails(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());
    }

    /**
     * An undecryptable EDK ahead of a good one must not stop the keyring: it
     * tries each candidate EDK in order and returns the first that unwraps.
     * The bad EDK keeps the good one's provider id and info, so it is a
     * candidate, but its ciphertext is zeroed.
     */
    @KeyringTest(name = "[raw-aes] bad then good EDK succeeds {0}", pairs = true)
    void onDecryptBadAndGoodEdkSucceeds(Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] wrappingKey = wrappingKey(alg, 0);

        EncryptionMaterials encrypted = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg),
            newEncryptionMaterials(encryptingMpl, EC));
        EncryptedDataKey good = encrypted.getEncryptedDataKeys().get(0);
        EncryptedDataKey bad = good.toBuilder()
            .ciphertext(ByteBuffer.wrap(new byte[bytes(good.getCiphertext()).length]))
            .build();

        DecryptionMaterials decrypted = rawAesKeyring(decryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(), List.of(bad, good));

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    @KeyringTest(name = "[raw-aes] no EDKs supplied, fails {0}")
    void onDecryptWithNoEdksFails(Mpl mpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;

        Keyring keyring = rawAesKeyring(mpl, NAMESPACE, KEY_NAME, wrappingKey(alg, 0), alg);
        keyring.onDecryptFails(mpl.newDecryptionMaterials(), List.of());
    }

    /**
     * The Raw AES keyring authenticates the serialized encryption context as
     * AAD, and a value longer than 2^16 - 1 bytes cannot be serialized (its
     * length is a u16). The Dafny TestRawAESKeyring.dfy uses 2^16 zero bytes;
     * this uses 2^16 ASCII 'a' characters, the same length in UTF-8.
     */
    @KeyringTest(name = "[raw-aes] unserializable encryption context rejected on encrypt {0}")
    void onEncryptUnserializableEcFails(Mpl mpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;

        Keyring keyring = rawAesKeyring(mpl, NAMESPACE, KEY_NAME, wrappingKey(alg, 0), alg);
        keyring.onEncryptFails(newEncryptionMaterials(mpl, UNSERIALIZABLE_EC));
    }

    @KeyringTest(
        name = "[raw-aes] unserializable encryption context rejected on decrypt {0}",
        pairs = true)
    void onDecryptUnserializableEcFails(Mpl encryptingMpl, Mpl decryptingMpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        byte[] wrappingKey = wrappingKey(alg, 0);

        EncryptionMaterials encrypted = onEncrypt(
            rawAesKeyring(encryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg),
            newEncryptionMaterials(encryptingMpl, EC));

        Keyring keyring = rawAesKeyring(decryptingMpl, NAMESPACE, KEY_NAME, wrappingKey, alg);
        keyring.onDecryptFails(
            decryptingMpl.newDecryptionMaterials(UNSERIALIZABLE_EC),
            encrypted.getEncryptedDataKeys());
    }

    // -----------------------------------------------------------------------
    // Checks every keyring must pass
    // -----------------------------------------------------------------------

    @Override
    public Keyring workingKeyring(Mpl mpl) {
        AesWrappingAlg alg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
        return rawAesKeyring(mpl, NAMESPACE, KEY_NAME, wrappingKey(alg, 0), alg);
    }

    /** One EDK for another key namespace and one for another key name. */
    @Override
    public List<EncryptedDataKey> edksThatDontMatch() {
        return List.of(
            edk("other-namespace", KEY_NAME, 1),
            edk(NAMESPACE, "other-key-name", 2));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static void assertRawAesEdk(EncryptedDataKey edk, String keyNamespace, String keyName) {
        assertEquals(keyNamespace, edk.getKeyProviderId(), "key provider id is the key namespace");

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

    private static Keyring rawAesKeyring(Mpl mpl, String keyNamespace, String keyName, byte[] wrappingKey,
            AesWrappingAlg alg) {
        return mpl.rawAesKeyring()
            .keyNamespace(keyNamespace)
            .keyName(keyName)
            .wrappingKey(wrappingKey)
            .wrappingAlg(alg)
            .create();
    }

    /** New encryption materials with {@code ec}, which must have the class's suite and no EDKs. */
    private static EncryptionMaterials newEncryptionMaterials(Mpl mpl, Map<String, String> ec) {
        EncryptionMaterials materials = mpl.newEncryptionMaterials(ec);
        assertEquals(SUITE.getValue(), materials.getAlgorithmSuiteId().getValue());
        assertEquals(0, materials.getEncryptedDataKeys().size());
        return materials;
    }

    /** OnEncrypt, whose materials must keep the class's encryption context. */
    private static EncryptionMaterials onEncrypt(Keyring keyring, EncryptionMaterials materials) {
        EncryptionMaterials out = keyring.onEncrypt(materials);
        assertEquals(EC, out.getEncryptionContext());
        return out;
    }

    /** The wrapping algorithm whose key is {@code keyLength} bytes long. */
    private static AesWrappingAlg wrappingAlg(int keyLength) {
        return switch (keyLength) {
            case 16 -> AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16;
            case 24 -> AesWrappingAlg.ALG_AES192_GCM_IV12_TAG16;
            case 32 -> AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
            default -> throw new IllegalArgumentException("no wrapping algorithm has a " + keyLength + "-byte key");
        };
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
}
