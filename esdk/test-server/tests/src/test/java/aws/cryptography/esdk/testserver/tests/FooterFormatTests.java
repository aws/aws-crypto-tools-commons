package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Footer serialization/presence conformance: a signing suite produces a footer and an
 * {@code aws-crypto-public-key} header entry; a non-signing suite produces neither.
 * Per-server structural properties (parsing is client-side), asserted by parsing the
 * produced message. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>FOOT-001</b> — the footer of a signed message is a 2-byte signature length
 *       followed by exactly that many signature bytes, ending the message
 *       ({@code spec/data-format/message-footer.md#structure}).</li>
 *   <li><b>FOOT-002</b> — signing suites produce a footer and an
 *       {@code aws-crypto-public-key} encryption-context entry; non-signing suites produce
 *       neither ({@code spec/data-format/message-footer.md#overview}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES), over both V1 and V2 signing/non-signing suites.
 */
class FooterFormatTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server footer-format plaintext".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PUBLIC_KEY_EC = "aws-crypto-public-key".getBytes(StandardCharsets.US_ASCII);

    /** A suite layout: which config/suite to encrypt with and whether it signs. */
    record Layout(String label, ESDKClientConfig config, ESDKAlgorithmSuiteId suite, boolean signing) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final ESDKClientConfig REQUIRE =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    private static final ESDKClientConfig FORBID =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);

    private static final List<Layout> LAYOUTS = List.of(
        new Layout("v2-signing", REQUIRE,
            ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, true),
        new Layout("v2-nonSigning", REQUIRE,
            ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, false),
        new Layout("v1-signing", FORBID,
            ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, true),
        new Layout("v1-nonSigning", FORBID,
            ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, false));

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            for (Layout layout : LAYOUTS) {
                cases.add(Arguments.of(target, layout));
            }
        }
        return cases;
    }

    /** True iff the raw header-AAD region contains the given ASCII key bytes. */
    private static boolean aadContains(EsdkMessage message, byte[] needle) {
        int start = message.aadContentOffset;
        int end = start + message.aadLength;
        for (int i = start; i + needle.length <= end; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (message.bytes[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    /**
     * FOOT-001 / FOOT-002: a signing suite yields a footer (2-byte length + that many bytes,
     * ending the message) and an {@code aws-crypto-public-key} header entry.
     */
    @ParameterizedTest(name = "footerPresentForSigning[{1}] {0}")
    @MethodSource("cases")
    void signingSuiteProducesFooterAndPublicKey(LanguageServerTarget target, Layout layout) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        if (!layout.signing()) {
            return;
        }
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), layout.config(), PLAINTEXT, Map.of(),
            layout.suite(), null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.footerOffset >= 0, target + " " + layout + ": a signing suite must have a footer");
        assertTrue(message.signatureLength > 0, target + " " + layout + ": the signature length must be > 0");
        assertEquals(ciphertext.length, message.footerOffset + 2 + message.signatureLength,
            target + " " + layout + ": the footer (2-byte length + signature) must end the message");
        assertTrue(aadContains(message, PUBLIC_KEY_EC),
            target + " " + layout + ": a signing suite must add an aws-crypto-public-key header entry");
    }

    /**
     * FOOT-002: a non-signing suite produces no footer (the final frame ends the message) and
     * no {@code aws-crypto-public-key} header entry.
     */
    @ParameterizedTest(name = "noFooterForNonSigning[{1}] {0}")
    @MethodSource("cases")
    void nonSigningSuiteHasNoFooterOrPublicKey(LanguageServerTarget target, Layout layout) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        if (layout.signing()) {
            return;
        }
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), layout.config(), PLAINTEXT, Map.of(),
            layout.suite(), null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(-1, message.footerOffset, target + " " + layout + ": a non-signing suite must have no footer");
        assertEquals(ciphertext.length, message.frames.get(message.frames.size() - 1).endOffset(),
            target + " " + layout + ": a non-signing message must end exactly at its final frame");
        assertFalse(aadContains(message, PUBLIC_KEY_EC),
            target + " " + layout + ": a non-signing suite must not add an aws-crypto-public-key header entry");
    }
}
