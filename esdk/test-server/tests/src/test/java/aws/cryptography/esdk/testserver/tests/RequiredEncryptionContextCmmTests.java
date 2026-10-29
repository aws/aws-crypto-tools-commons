package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Required-Encryption-Context CMM conformance. The CMM drops the required keys from the
 * header on encrypt and demands them, reproduced, on decrypt. Every test runs over the
 * cross-language pairwise matrix, with each side gated on the features it uses. Catalog
 * behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>CMM-007</b> — round-trips when the required keys are reproduced on decrypt
 *       ({@code spec/framework/required-encryption-context-cmm.md#decrypt-materials}).</li>
 *   <li><b>CMM-008</b> — decrypt fails when the required keys are not correctly reproduced: none
 *       supplied, the required key missing, a required key given a wrong value, or an extra pair
 *       reproduced that the message was not encrypted with
 *       ({@code spec/framework/required-encryption-context-cmm.md#decrypt-materials}).</li>
 *   <li><b>EC-011</b> — a Required-EC CMM configured with the reserved {@code aws-crypto-public-key}
 *       as a required key is rejected on encrypt (a per-server property)
 *       ({@code spec/framework/required-encryption-context-cmm.md#get-encryption-materials}).</li>
 * </ul>
 *
 * <p>The message context is {@code purpose} and {@code tenant}, with only {@code purpose} required,
 * so the header keeps {@code tenant} and drops {@code purpose}. This matches the Dafny
 * TestRequiredEncryptionContext tests.
 *
 * <p>CMM-007 and CMM-008 decrypt with each {@link DecryptCmm}. The Default CMM row is the
 * one a server without the Required-EC CMM (e.g. the native Rust ESDK) can run.
 *
 * <p>Fully offline (Raw-AES). ESDK-originated failures surface as {@link ESDKClientError}.
 */
class RequiredEncryptionContextCmmTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server required-ec plaintext".getBytes(StandardCharsets.UTF_8);
    private static final List<String> REQUIRED_KEYS = List.of("purpose");
    private static final Map<String, String> FULL_CONTEXT =
        Map.of("purpose", "test", "tenant", "acme");
    /** The required pair, which the header does not store. */
    private static final Map<String, String> REPRODUCED = Map.of("purpose", "test");

    private static final Set<String> FEATURES = Set.of("required-encryption-context", "raw-aes");

    /** The CMM that the decrypting server uses, and the features that it needs for it. */
    enum DecryptCmm {
        REQUIRED_EC(Set.of("required-encryption-context", "raw-aes")),
        DEFAULT(Set.of("raw-aes", "default-cmm-reproduced-encryption-context"));

        final Set<String> features;

        DecryptCmm(Set<String> features) {
            this.features = features;
        }

        ESDKClientConfig config() {
            return this == REQUIRED_EC ? RequiredEncryptionContextCmmTests.config() : EsdkClientConfigs.rawAes();
        }
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<Arguments> pairsByDecryptCmm() {
        List<Arguments> cases = new ArrayList<>();
        for (TargetPair pair : pairs()) {
            for (DecryptCmm cmm : DecryptCmm.values()) {
                cases.add(Arguments.of(pair, cmm));
            }
        }
        return cases;
    }

    private static ESDKClientConfig config() {
        return EsdkClientConfigs.rawAesRequiredEc(REQUIRED_KEYS);
    }

    /** Gate the encryptor on {@code encryptFeatures} and the decryptor on {@code decryptFeatures}. */
    private static void requireSides(TargetPair pair, Set<String> encryptFeatures,
            Set<String> decryptFeatures) {
        FeatureGate.require(encryptFeatures, new TargetPair(pair.encryptTarget(), pair.encryptTarget()));
        FeatureGate.require(decryptFeatures, new TargetPair(pair.decryptTarget(), pair.decryptTarget()));
    }

    /** Encrypt with the Required-EC CMM, so the header drops {@code purpose}. */
    private static byte[] encrypt(TargetPair pair, DecryptCmm cmm) {
        requireSides(pair, FEATURES, cmm.features);
        return EsdkOps.encrypt(pair.encryptEndpoint(), config(), PLAINTEXT, FULL_CONTEXT, null, null);
    }

    /**
     * CMM-007: reproducing the required pair on decrypt round-trips. Dafny parity:
     * TestRemoveOnEncryptRemoveAndSupplyOnDecryptHappyCase (Required-EC CMM) and
     * TestRemoveOnEncryptAndSupplyOnDecryptHappyCase (Default CMM).
     */
    @ParameterizedTest(name = "reproducedRequiredEcDecrypts[{1}] {0}")
    @MethodSource("pairsByDecryptCmm")
    void decryptSucceedsWhenRequiredContextReproduced(TargetPair pair, DecryptCmm cmm) {
        byte[] ciphertext = encrypt(pair, cmm);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), cmm.config(), ciphertext, REPRODUCED);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt with the required pair reproduced must recover the plaintext (" + pair + ", "
                + cmm + ")");
    }

    /**
     * A Default-CMM message stores all of its context, and the Required-EC CMM decrypts it when
     * the required pair is reproduced. Dafny parity (TestRemoveOnDecryptIsBackwardsCompatibleHappyCase).
     */
    @ParameterizedTest(name = "requiredEcCmmDecryptsFullyStoredMessage {0}")
    @MethodSource("pairs")
    void decryptSucceedsWithRequiredEcCmmOnFullyStoredMessage(TargetPair pair) {
        requireSides(pair, Set.of("raw-aes"), FEATURES);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAes(),
            PLAINTEXT, FULL_CONTEXT, null, null);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config(), ciphertext, REPRODUCED);
        assertArrayEquals(PLAINTEXT, recovered,
            "the Required-EC CMM must decrypt a message that stored all of its context (" + pair + ")");
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
    void requiredKeysAreExcludedFromTheSerializedHeader(TargetPair pair) {
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

    /**
     * CMM-008: decrypt with NO reproduced context fails (the required pair is not on the wire).
     * Dafny parity (TestRemoveECAndNotSupplyOnDecryptFailure).
     */
    @ParameterizedTest(name = "missingReproducedEcRejected[{1}] {0}")
    @MethodSource("pairsByDecryptCmm")
    void decryptFailsWhenNoContextReproduced(TargetPair pair, DecryptCmm cmm) {
        byte[] ciphertext = encrypt(pair, cmm);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), cmm.config(), ciphertext),
            "decrypt without reproducing the required encryption context must fail (" + pair + ", "
                + cmm + ")");
    }

    /**
     * CMM-008: decrypt reproducing only the stored pair, without the required one, fails.
     * Dafny parity (TestRemoveECAndSupplyWithMissingRequiredValueDecryptFailure).
     */
    @ParameterizedTest(name = "partialReproducedEcRejected[{1}] {0}")
    @MethodSource("pairsByDecryptCmm")
    void decryptFailsWhenRequiredKeyMissing(TargetPair pair, DecryptCmm cmm) {
        byte[] ciphertext = encrypt(pair, cmm);
        Map<String, String> partial = Map.of("tenant", "acme");  // missing "purpose"
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), cmm.config(), ciphertext, partial),
            "decrypt missing the required reproduced key must fail (" + pair + ", " + cmm + ")");
    }

    /**
     * CMM-008: decrypt reproducing the required key with the wrong value fails.
     * Dafny parity (TestRemoveECAndSupplyMismatchedReprECFailure).
     */
    @ParameterizedTest(name = "wrongReproducedEcValueRejected[{1}] {0}")
    @MethodSource("pairsByDecryptCmm")
    void decryptFailsWhenRequiredValueWrong(TargetPair pair, DecryptCmm cmm) {
        byte[] ciphertext = encrypt(pair, cmm);
        Map<String, String> wrong = Map.of("purpose", "WRONG");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), cmm.config(), ciphertext, wrong),
            "decrypt reproducing the required key with a wrong value must fail (" + pair + ", "
                + cmm + ")");
    }

    /**
     * CMM-008: decrypt reproducing the required pair plus a pair the message was not encrypted
     * with fails. The Default CMM adds the extra pair to the decryption materials, so the unwrap
     * sees a context that the wrapping never bound.
     */
    @ParameterizedTest(name = "supersetReproducedEcRejected {0}")
    @MethodSource("pairs")
    void decryptFailsWhenExtraKeyReproduced(TargetPair pair) {
        byte[] ciphertext = encrypt(pair, DecryptCmm.DEFAULT);
        Map<String, String> superset = Map.of("purpose", "test", "extra", "not-on-the-message");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), EsdkClientConfigs.rawAes(),
                ciphertext, superset),
            "decrypt reproducing a pair the message was not encrypted with must fail (" + pair + ")");
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
            new TargetPair(target, target));
        ESDKClientConfig config = EsdkClientConfigs.rawAesRequiredEc(List.of("aws-crypto-public-key"));
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), null, null),
            "encrypt with the reserved aws-crypto-public-key as a required encryption-context key "
                + "must be rejected (" + target + ")");
    }
}
