package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Raw-keyring behavior conformance. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>KEYRING-003</b> — raw-key decrypt succeeds whenever at least one supplied EDK matches a
 *       held wrapping key: a message wrapped to two keyrings decrypts under a keyring holding only
 *       the second key ({@code spec/framework/raw-aes-keyring.md#ondecrypt}). Asserts only the
 *       decryptor's EDK matching, so it runs decrypt-side
 *       ({@link ReferenceImplementation#decryptSide}); the multi-keyring round trips in
 *       {@code MaterialsRoundTripTests} keep the pairwise producer coverage.</li>
 *   <li><b>KEYRING-053</b> — a multi-keyring with children but no generator cannot create a data
 *       key, so encrypt fails ({@code spec/framework/multi-keyring.md#onencrypt}). Encrypt-time
 *       validation is a per-server property, so it runs against every target.</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). ESDK-originated failures surface as {@link ESDKClientError}.
 */
class RawKeyringBehaviorTests {

    private static final Set<String> FEATURES = Set.of("raw-aes", "multi");

    private static final byte[] PLAINTEXT =
        "esdk-test-server raw-keyring-behavior plaintext".getBytes(StandardCharsets.UTF_8);

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(FEATURES);
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /** KEYRING-003: a two-keyring message decrypts under a keyring holding only the second key. */
    @ParameterizedTest(name = "subsetKeyringDecrypts {0}")
    @MethodSource("decryptSide")
    void decryptSucceedsWithASubsetKeyring(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        // Encrypt to a multi-keyring (generator "a" + child "b") => two EDKs.
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAesMulti(), PLAINTEXT);
        // Decrypt with a keyring holding only key "b" — it matches the second EDK.
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAesBOnly(), ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "a message wrapped to two keyrings must decrypt under a keyring holding only one of the "
                + "matching wrapping keys (" + pair + ")");
    }

    /**
     * KEYRING-053: a multi-keyring with children but no generator cannot create a data key, so
     * encrypt fails (only a generator can generate material).
     */
    @ParameterizedTest(name = "childrenOnlyMultiCannotEncrypt {0}")
    @MethodSource("targets")
    void childrenOnlyMultiKeyringCannotEncrypt(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, new EndpointPair(target, target));
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), EsdkClientConfigs.rawAesChildrenOnlyMulti(), PLAINTEXT),
            "a multi-keyring with no generator must fail to encrypt (nothing can create a data key) ("
                + target + ")");
    }

    /**
     * Decrypt continues past an EDK whose unwrap is ATTEMPTED and fails hard. The message
     * carries an RSA EDK and an AES EDK; the decryptor's RSA keyring matches the RSA EDK's
     * provider fields but holds a different private key, so the unwrap runs and throws — and
     * decrypt must still succeed through the AES EDK
     * ({@code spec/framework/multi-keyring.md#ondecrypt}: collect the child failure and
     * continue). Distinct from {@code subsetKeyringDecrypts}, where the unmatched EDK is
     * skipped without ever attempting an unwrap; the ESDK for Python aborted the whole decrypt
     * on exactly this attempted-and-failed path until it was fixed.
     */
    @ParameterizedTest(name = "hardUnwrapFailureContinues {0}")
    @MethodSource("pairs")
    void decryptContinuesPastHardEdkUnwrapFailure(EndpointPair pair) {
        FeatureGate.require(Set.of("raw-aes", "raw-rsa", "multi"), pair);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(),
            EsdkClientConfigs.rawRsaPlusAesMulti(), PLAINTEXT);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(),
            EsdkClientConfigs.rawRsaMismatchedKeyPlusAesMulti(), ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt must continue to the next EDK after an attempted unwrap fails hard ("
                + pair + ")");
    }

    /**
     * Non-ASCII key namespace and key name survive the EDK provider fields exactly. The header
     * stores each field as UTF-8 bytes behind a 2-byte BYTE length
     * ({@code spec/data-format/message-header.md#encrypted-data-key-entries}); an implementation
     * that measures the length in characters instead of encoded bytes emits a self-consistent
     * but truncated field — the message authenticates and no decryptor can ever match the
     * keyring again, which is how the ESDK for Python permanently lost data until its 2018
     * serializer fix. Asserted on the wire, then round-tripped cross-language.
     */
    @ParameterizedTest(name = "nonAsciiProviderFieldsRoundTrip {0}")
    @MethodSource("pairs")
    void nonAsciiKeyNamespaceAndNameRoundTrip(EndpointPair pair) {
        FeatureGate.require(Set.of("raw-aes"), pair);
        String namespace = "\u6a19\u6e96-namespace";        // 標準-namespace
        String keyName = "raw-aes-\u043a\u043b\u044e\u0447"; // raw-aes-ключ
        ESDKClientConfig config = EsdkClientConfigs.rawAesNamed(namespace, keyName);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT);

        EsdkMessage message = EsdkMessage.parse(ciphertext);
        byte[] namespaceUtf8 = namespace.getBytes(StandardCharsets.UTF_8);
        byte[] keyNameUtf8 = keyName.getBytes(StandardCharsets.UTF_8);
        // First EDK entry: providerIdLen(2) ‖ providerId ‖ providerInfoLen(2) ‖ providerInfo ...
        int pos = message.edkCountOffset + 2;
        int providerIdLen = u16(message.bytes, pos);
        pos += 2;
        assertEquals(namespaceUtf8.length, providerIdLen,
            pair + ": the provider-id length must count UTF-8 bytes, not characters");
        assertArrayEquals(namespaceUtf8, Arrays.copyOfRange(message.bytes, pos, pos + providerIdLen),
            pair + ": the provider id must be the exact UTF-8 encoding of the key namespace");
        pos += providerIdLen;
        int providerInfoLen = u16(message.bytes, pos);
        pos += 2;
        // Raw-AES provider info = keyName ‖ tagLenBits(4) ‖ ivLen(4) ‖ iv(12).
        assertEquals(keyNameUtf8.length + 4 + 4 + 12, providerInfoLen,
            pair + ": the provider-info length must count the key name's UTF-8 bytes");
        assertArrayEquals(keyNameUtf8, Arrays.copyOfRange(message.bytes, pos, pos + keyNameUtf8.length),
            pair + ": the provider info must begin with the exact UTF-8 encoding of the key name");

        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
            pair + ": a non-ASCII key namespace/name must round-trip");
    }

    private static int u16(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }
}
