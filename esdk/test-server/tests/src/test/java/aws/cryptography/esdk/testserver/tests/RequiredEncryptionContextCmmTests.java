package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Required-Encryption-Context CMM conformance. The CMM drops the required keys from the
 * header on encrypt and demands them, reproduced, on decrypt. The CMM-007 round trip runs
 * over the cross-language pairwise matrix; the CMM-008 rejections assert only the
 * decryptor's reproduction check, so they run decrypt-side
 * ({@link ReferenceImplementation#decryptSide}). Catalog behaviors
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>CMM-007</b> — round-trips when the required keys are reproduced exactly on decrypt
 *       ({@code spec/framework/required-encryption-context-cmm.md#decrypt-materials}). Also
 *       proven with the plain Default CMM on the decrypt leg (Dafny
 *       TestRemoveOnEncryptRemoveAndSupplyOnDecryptHappyCase), decrypt-side.</li>
 *   <li><b>CMM-008</b> — decrypt fails when the required keys are not correctly reproduced: none
 *       supplied, the required key missing, or a required key given a wrong value
 *       ({@code spec/framework/required-encryption-context-cmm.md#decrypt-materials}).</li>
 *   <li><b>EC-011</b> — a Required-EC CMM configured with the reserved {@code aws-crypto-public-key}
 *       as a required key is rejected on encrypt (a per-server property)
 *       ({@code spec/framework/required-encryption-context-cmm.md#get-encryption-materials}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). The required keys never appear on the wire, so decrypt must obtain
 * them from the reproduced context. ESDK-originated failures surface as {@link ESDKClientError}.
 */
class RequiredEncryptionContextCmmTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server required-ec plaintext".getBytes(StandardCharsets.UTF_8);
    private static final List<String> REQUIRED_KEYS = List.of("purpose", "tenant");
    private static final Map<String, String> FULL_CONTEXT =
        Map.of("purpose", "test", "tenant", "acme");

    private static final Set<String> FEATURES = Set.of("required-encryption-context", "raw-aes");

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(FEATURES);
    }

    private static ESDKClientConfig config() {
        return EsdkClientConfigs.rawAesRequiredEc(REQUIRED_KEYS);
    }

    /** Encrypt with the required-EC CMM and the full context (required keys dropped from the header). */
    private static byte[] encrypt(EndpointPair pair) {
        FeatureGate.require(FEATURES, pair);
        return EsdkOps.encrypt(pair.encryptEndpoint(), config(), PLAINTEXT, FULL_CONTEXT, null, null);
    }

    /** CMM-007: reproducing the required context exactly on decrypt round-trips. */
    @ParameterizedTest(name = "reproducedRequiredEcDecrypts {0}")
    @MethodSource("pairs")
    void decryptSucceedsWhenRequiredContextReproduced(EndpointPair pair) {
        byte[] ciphertext = encrypt(pair);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, FULL_CONTEXT);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt with the required keys reproduced exactly must recover the plaintext (" + pair + ")");
    }

    /**
     * Dafny parity (TestRemoveOnEncryptRemoveAndSupplyOnDecryptHappyCase): a message encrypted
     * with the required-EC CMM decrypts under the plain Default CMM when the dropped context is
     * reproduced — the decryptor needs no required-EC CMM of its own, though supplying the
     * reproduced context on decrypt is itself the required-encryption-context capability, so
     * both legs gate on it.
     */
    @ParameterizedTest(name = "defaultCmmDecryptsWithReproducedContext {0}")
    @MethodSource("decryptSide")
    void decryptSucceedsWithDefaultCmmWhenRequiredContextReproduced(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config(), PLAINTEXT,
            FULL_CONTEXT, null, null);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAes(),
            ciphertext, FULL_CONTEXT);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt with the Default CMM and the dropped context reproduced must recover the "
                + "plaintext (" + pair + ")");
    }

    /**
     * The header's serialized encryption context MUST NOT contain the pairs listed as required
     * encryption context keys, while pairs not listed stay serialized
     * ({@code spec/client-apis/encrypt.md#construct-the-header}). Proven on the wire with a mixed
     * context: the required key is absent from the header AAD, the non-required key present, and
     * the message still round-trips with the required pair reproduced — so the dropped pair is
     * authenticated without being stored.
     */
    @ParameterizedTest(name = "requiredKeysExcludedFromHeaderAad {0}")
    @MethodSource("pairs")
    void requiredKeysAreExcludedFromTheSerializedHeader(EndpointPair pair) {
        FeatureGate.require(Set.of("required-encryption-context", "raw-aes"), pair);
        ESDKClientConfig config = EsdkClientConfigs.rawAesRequiredEc(List.of("purpose"));
        Map<String, String> context = Map.of("purpose", "test", "shared", "value");
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, context,
            ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, null);

        List<String> headerKeys = headerAadKeys(EsdkMessage.parse(ciphertext));
        assertFalse(headerKeys.contains("purpose"),
            pair + ": a required encryption-context key must not be serialized in the header, got "
                + headerKeys);
        assertTrue(headerKeys.contains("shared"),
            pair + ": a non-required encryption-context pair must stay serialized in the header, got "
                + headerKeys);

        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext,
            Map.of("purpose", "test"));
        assertArrayEquals(PLAINTEXT, recovered,
            pair + ": the mixed-context message must round-trip with the required pair reproduced");
    }

    /** The AAD's keys in wire order: count(2), then per pair keyLen(2) key valLen(2) val. */
    private static List<String> headerAadKeys(EsdkMessage message) {
        byte[] b = message.bytes;
        int pos = message.aadContentOffset;
        if (message.aadLength == 0) {
            return List.of();
        }
        int pairCount = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
        pos += 2;
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < pairCount; i++) {
            int keyLen = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2;
            keys.add(new String(b, pos, keyLen, StandardCharsets.UTF_8));
            pos += keyLen;
            int valLen = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2 + valLen;
        }
        return keys;
    }

    /** CMM-008: decrypt with NO reproduced context fails (the required keys are not on the wire). */
    @ParameterizedTest(name = "missingReproducedEcRejected {0}")
    @MethodSource("decryptSide")
    void decryptFailsWhenNoContextReproduced(ReferencePair pair) {
        byte[] ciphertext = encrypt(pair.asEndpointPair());
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext),
            "decrypt without reproducing the required encryption context must fail (" + pair + ")");
    }

    /** CMM-008: decrypt reproducing only some of the required keys fails. */
    @ParameterizedTest(name = "partialReproducedEcRejected {0}")
    @MethodSource("decryptSide")
    void decryptFailsWhenRequiredKeyMissing(ReferencePair pair) {
        byte[] ciphertext = encrypt(pair.asEndpointPair());
        Map<String, String> partial = Map.of("purpose", "test");  // missing "tenant"
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, partial),
            "decrypt missing a required reproduced key must fail (" + pair + ")");
    }

    /** CMM-008: decrypt reproducing a required key with the wrong value fails. */
    @ParameterizedTest(name = "wrongReproducedEcValueRejected {0}")
    @MethodSource("decryptSide")
    void decryptFailsWhenRequiredValueWrong(ReferencePair pair) {
        byte[] ciphertext = encrypt(pair.asEndpointPair());
        Map<String, String> wrong = Map.of("purpose", "test", "tenant", "WRONG");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, wrong),
            "decrypt reproducing a required key with a wrong value must fail (" + pair + ")");
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /**
     * EC-011: a Required-EC CMM that lists the reserved {@code aws-crypto-public-key} as a required
     * key must fail on encrypt. The reserved key is only supplied as a <em>required</em> key (never
     * in the caller's encryption context, which would instead trip the reserved-key-in-context rule),
     * so the rejection is attributable to the reserved-as-required configuration. Per-server property.
     */
    @ParameterizedTest(name = "reservedKeyAsRequiredRejected {0}")
    @MethodSource("targets")
    void encryptRejectsReservedKeyAsRequiredEcKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of("required-encryption-context", "raw-aes"),
            new EndpointPair(target, target));
        ESDKClientConfig config = EsdkClientConfigs.rawAesRequiredEc(List.of("aws-crypto-public-key"));
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), null, null),
            "encrypt with the reserved aws-crypto-public-key as a required encryption-context key "
                + "must be rejected (" + target + ")");
    }
}
