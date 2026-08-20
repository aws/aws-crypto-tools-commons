package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureGate;

import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Message region ordering conformance: the message begins with the header, and the body begins
 * exactly at the header's end (the header-authentication boundary), for both message-format
 * versions. Per-server structural property, asserted by parsing the produced message. Catalog
 * behavior (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>HDR-026</b> — the message begins with the header; the body begins exactly at the
 *       header's end ({@code spec/data-format/message.md#structure}).</li>
 * </ul>
 *
 * <p>A frame length smaller than the plaintext is used so the body's first frame is a regular
 * frame, whose 4-byte sequence number ({@code 1}) sits at the header/body boundary — a wrong
 * boundary would not read back as sequence number 1. Region ordering is keyring-independent, so
 * each target runs once under the keyring it supports (Raw-AES where available, else the
 * hierarchical keyring the native Rust ESDK supports), over a V2 committing and a V1 non-signing
 * layout.
 */
class MessageRegionOrderingTests {

    /** Larger than FRAME_LENGTH so the first body frame is a regular frame (sequence number 1). */
    private static final byte[] PLAINTEXT = new byte[700];
    private static final long FRAME_LENGTH = 512L;

    /** A message-format layout: the policy/suite to encrypt with and the expected version byte. */
    record Layout(String label, ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite, int versionByte) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final Layout V2 = new Layout("v2",
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, 2);
    private static final Layout V1 = new Layout("v1",
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, 1);

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            cases.add(Arguments.of(target, V2));
            cases.add(Arguments.of(target, V1));
        }
        return cases;
    }

    /**
     * The single keyring the target supports (Raw-AES, else hierarchical), gated so the target is a
     * visible skip when it supports neither. Region ordering is keyring-independent, so the target
     * runs once, under this keyring.
     */
    private static ConformanceKeyring keyringFor(TargetPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring;
    }

    private static long u32(byte[] b, int i) {
        return ((long) (b[i] & 0xFF) << 24) | ((b[i + 1] & 0xFF) << 16)
            | ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
    }

    /**
     * HDR-026: the message begins with the header (version byte at offset 0) and the body begins
     * exactly at the header's end — the first regular frame's sequence number (1) sits at the
     * header-authentication boundary.
     */
    @ParameterizedTest(name = "regionOrdering[{1}] {0}")
    @MethodSource("cases")
    void headerPrecedesBodyAtExactBoundary(LanguageServerTarget target, Layout layout) {
        ESDKClientConfig config = keyringFor(new TargetPair(target, target)).config(layout.policy());
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(),
            layout.suite(), FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(layout.versionByte(), ciphertext[0] & 0xFF,
            target + " " + layout + ": the message must begin with the header version byte");
        assertEquals(1L, u32(ciphertext, message.bodyStart),
            target + " " + layout + ": the body's first frame (sequence number 1) must begin exactly "
                + "at the header's end");
    }
}
