package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureGate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Encryption-context wire-serialization conformance: assert the header AAD the server
 * produced matches the canonical encryption-context serialization. Per-server structural
 * properties, asserted by parsing the header AAD region. Catalog behaviors
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>EC-031 / HDR-002</b> — an empty encryption context serializes to a 2-byte
 *       zero-length AAD with no key-value-pairs body
 *       ({@code spec/framework/structures.md#serialization}).</li>
 *   <li><b>EC-030 / HDR-003</b> — a non-empty encryption context serializes as a pair count
 *       followed by length-prefixed key/value pairs, keys in ascending unsigned-byte order
 *       ({@code spec/framework/structures.md#serialization}).</li>
 * </ul>
 *
 * <p>The encryption-context serialization is keyring-independent, so each per-server case runs
 * once under the keyring the target supports ({@link ConformanceKeyring}): Raw-AES where
 * available, otherwise the hierarchical keyring, the one the native Rust ESDK supports. Uses a
 * non-signing suite so the header AAD contains exactly the caller's encryption context (a signing
 * suite would add an {@code aws-crypto-public-key} entry).
 */
class EncryptionContextFormatTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server ec-format plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;
    /** Non-signing so the header AAD holds only the caller's context. */
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /**
     * The single keyring both endpoints support (Raw-AES, else hierarchical), gated so the pair is
     * a visible skip when they share none. Resolved before producing a message.
     */
    private static ESDKClientConfig configFor(TargetPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring.config(POLICY);
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    /** EC-031: an empty encryption context serializes to a 2-byte zero length with no body. */
    @ParameterizedTest(name = "emptyEcZeroLength {0}")
    @MethodSource("targets")
    void emptyEncryptionContextSerializesToZeroLength(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), SUITE, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(0, message.aadLength,
            target + ": an empty encryption context must serialize to a zero-length AAD");
    }

    /**
     * EC-030: the header AAD lists the encryption-context keys in ascending unsigned-byte
     * order, as length-prefixed pairs after a 2-byte pair count.
     */
    @ParameterizedTest(name = "ecKeysCanonicallyOrdered {0}")
    @MethodSource("targets")
    void encryptionContextKeysAreCanonicallyOrdered(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        // Insert keys out of order; the wire form must sort them.
        Map<String, String> ec = new java.util.LinkedHashMap<>();
        ec.put("zebra", "1");
        ec.put("alpha", "2");
        ec.put("mango", "3");
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, ec, SUITE, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.aadLength > 0, target + ": non-empty EC must produce a non-empty AAD");

        int pos = message.aadContentOffset;
        int pairCount = u16(ciphertext, pos);
        pos += 2;
        assertEquals(3, pairCount, target + ": AAD must declare 3 key-value pairs");

        List<String> keys = new ArrayList<>();
        for (int i = 0; i < pairCount; i++) {
            int keyLen = u16(ciphertext, pos);
            pos += 2;
            keys.add(new String(ciphertext, pos, keyLen, StandardCharsets.UTF_8));
            pos += keyLen;
            int valLen = u16(ciphertext, pos);
            pos += 2 + valLen;
        }
        assertEquals(List.of("alpha", "mango", "zebra"), keys,
            target + ": encryption-context keys must be serialized in ascending unsigned-byte order");
    }

    /**
     * EC-030 (UTF-8 byte order, not UTF-16): keys MUST sort by their UTF-8 encoded binary value
     * ({@code spec/framework/structures.md#serialization}). Chosen so the two orders disagree:
     * U+FF61 (UTF-8 {@code EF BD A1}) precedes U+10000 (UTF-8 {@code F0 90 80 80}) in UTF-8 byte
     * order, but Java's native UTF-16 code-unit order puts U+10000 (surrogate {@code D800 DC00})
     * FIRST — so a server sorting by its language's default string order serializes them backwards.
     * ASCII-key tests cannot catch this. Added by gap analysis; not a catalog behavior.
     */
    @ParameterizedTest(name = "ecKeysSortedByUtf8Bytes {0}")
    @MethodSource("targets")
    void encryptionContextKeysSortByUtf8BytesNotUtf16(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        String bmpKey = "\uff61";                 // U+FF61,  UTF-8 EF BD A1
        String astralKey = "\ud800\udc00";        // U+10000, UTF-8 F0 90 80 80
        Map<String, String> ec = new java.util.LinkedHashMap<>();
        ec.put(astralKey, "1");                   // insert in UTF-16 order (astral first)
        ec.put(bmpKey, "2");
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, ec, SUITE, null);
        assertEquals(List.of(bmpKey, astralKey), parseAadKeys(EsdkMessage.parse(ciphertext)),
            target + ": keys must serialize in UTF-8 byte order (U+FF61 before U+10000), not the "
                + "UTF-16 code-unit order");
        // Cross-check the wire order survives a real decrypt (the header is authenticated).
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(target.endpoint(), config, ciphertext),
            target + ": the astral-key message must still decrypt");
    }

    /**
     * An encryption-context entry with an empty-string VALUE is legal (the spec constrains keys,
     * not values) and divergence-prone: assert it serializes as a zero value length on the wire and
     * round-trips. Added by gap analysis; not a catalog behavior.
     */
    @ParameterizedTest(name = "emptyEcValueRoundTrips {0}")
    @MethodSource("targets")
    void emptyEncryptionContextValueSerializesAndRoundTrips(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new TargetPair(target, target));
        Map<String, String> ec = Map.of("empty-value-key", "");
        KnownBugGate.gate("encrypt-rejects-empty-encryption-context-value", target.language(), () -> {
            byte[] ciphertext = assertDoesNotThrow(
                () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, ec, SUITE, null),
                target + ": encrypt with an empty encryption-context value must be accepted");
            EsdkMessage message = EsdkMessage.parse(ciphertext);
            // Walk the single pair: count(2) keyLen(2) key valLen(2) — the value length must be 0.
            int pos = message.aadContentOffset;
            assertEquals(1, u16(ciphertext, pos), target + ": AAD must declare exactly one pair");
            pos += 2;
            int keyLen = u16(ciphertext, pos);
            pos += 2 + keyLen;
            assertEquals(0, u16(ciphertext, pos),
                target + ": an empty encryption-context value must serialize as a zero value length");
            assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(target.endpoint(), config, ciphertext),
                target + ": the empty-value message must decrypt");
        });
    }

    /** The AAD's keys in wire order: count(2), then per pair keyLen(2) key valLen(2) val. */
    private static List<String> parseAadKeys(EsdkMessage message) {
        byte[] b = message.bytes;
        int pos = message.aadContentOffset;
        int pairCount = u16(b, pos);
        pos += 2;
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < pairCount; i++) {
            int keyLen = u16(b, pos);
            pos += 2;
            keys.add(new String(b, pos, keyLen, StandardCharsets.UTF_8));
            pos += keyLen;
            int valLen = u16(b, pos);
            pos += 2 + valLen;
        }
        return keys;
    }
}
