package aws.cryptography.esdk.testserver.tests;

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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Positive header-structure conformance: encrypt a message and assert the header the
 * server produced parses to the expected fields for its format version. Per-server
 * structural properties. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>HDR-001 / HDR-009</b> — a V1 header carries the version, suite id, 16-byte message
 *       id, EDKs, framed content type, and frame length
 *       ({@code spec/data-format/message-header.md#header-body-version-1-0}).</li>
 *   <li><b>HDR-007 / HDR-010</b> — a V2 header carries the version, suite id, 32-byte message
 *       id, EDKs, framed content type, frame length, and algorithm-suite data
 *       ({@code spec/data-format/message-header.md#header-body-version-2-0}).</li>
 *   <li><b>HDR-004</b> — the EDK section declares a positive count
 *       ({@code spec/data-format/message-header.md#encrypted-data-keys}).</li>
 * </ul>
 *
 * <p>Non-signing suites, so the header carries a single EDK and no footer. Header structure is
 * keyring-independent, so each target runs once under the keyring it supports (Raw-AES where
 * available, else the hierarchical keyring the native Rust ESDK supports).
 */
class HeaderStructureTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server header-structure plaintext".getBytes(StandardCharsets.UTF_8);

    /** Expected header facts for a chosen suite: format version, 2-byte suite id, message-id length. */
    record Expected(String label, ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite,
                    int version, int suiteId, int messageIdLength) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final Expected V2_COMMITTING = new Expected("v2-committing",
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, 2, 0x0478, 32);

    private static final Expected V1_NON_SIGNING = new Expected("v1-nonSigning",
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, 1, 0x0178, 16);

    private static final List<Expected> EXPECTATIONS = List.of(V2_COMMITTING, V1_NON_SIGNING);

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            for (Expected expected : EXPECTATIONS) {
                cases.add(Arguments.of(target, expected));
            }
        }
        return cases;
    }

    /**
     * The single keyring the target supports (Raw-AES, else hierarchical), gated so the target is a
     * visible skip when it supports neither. Header structure is keyring-independent, so the target
     * runs once, under this keyring.
     */
    private static ConformanceKeyring keyringFor(EndpointPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring;
    }

    @ParameterizedTest(name = "headerFields[{1}] {0}")
    @MethodSource("cases")
    void headerParsesToExpectedFields(LanguageServerTarget target, Expected expected) {
        ESDKClientConfig config = keyringFor(new EndpointPair(target, target)).config(expected.policy());
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(),
            expected.suite(), null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);

        assertEquals(expected.version(), message.version,
            target + " " + expected + ": message-format version");
        assertEquals(expected.suiteId(), message.algorithmSuiteId,
            target + " " + expected + ": algorithm-suite id");
        assertEquals(expected.messageIdLength(), message.messageIdLength,
            target + " " + expected + ": message-id length");
        assertTrue(message.edkCount >= 1,
            target + " " + expected + ": the header must declare at least one EDK");
        assertEquals(0x02, ciphertext[message.contentTypeOffset] & 0xFF,
            target + " " + expected + ": content type must be framed (0x02)");
        assertEquals(4096L, message.frameLength,
            target + " " + expected + ": default frame length must be 4096");
    }
}
