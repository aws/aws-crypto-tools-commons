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
 * Wire-shape conformance for every algorithm suite in the ESDK suite matrix
 * ({@code spec/framework/algorithm-suites.md#supported-algorithm-suites}). For each suite, the
 * emitted message is parsed and its header/footer shape asserted:
 *
 * <ul>
 *   <li>the header's 2-byte algorithm-suite id equals the suite the caller requested
 *       ({@code spec/data-format/message-header.md#algorithm-suite-id}) — a round-trip alone
 *       cannot prove this, because a decryptor obeys whatever suite the self-describing header
 *       declares, so an encryptor that silently substitutes a different suite still
 *       round-trips;</li>
 *   <li>the message-format version matches the suite's generation — committing suites are
 *       serialized as version 2.0, all others as version 1.0
 *       ({@code spec/data-format/message-header.md#supported-versions});</li>
 *   <li>the message id is 128 bits in V1 and 256 bits in V2
 *       ({@code spec/data-format/message-header.md#message-id});</li>
 *   <li>V1 only: the reserved field is the 4-byte zero sequence
 *       ({@code spec/data-format/message-header.md#reserved}) and the IV-length byte equals the
 *       suite's IV length of 12 ({@code spec/data-format/message-header.md#iv-length});</li>
 *   <li>a footer is present exactly for signing suites
 *       ({@code spec/data-format/message-footer.md}).</li>
 * </ul>
 *
 * <p>{@link HeaderStructureTests} asserts the per-version header layout in depth for two
 * representative suites; this class completes the matrix across the full suite enum with the
 * suite-identity assertion. Encrypt legality per commitment policy is {@link KeyCommitmentTests}'
 * concern; here each suite is encrypted under a policy that permits it.
 *
 * <p>Wire shape is keyring-independent, so each target runs once under the keyring it supports
 * (Raw-AES where available, else the hierarchical keyring the native Rust ESDK supports).
 * Encrypt-side wire shape is a per-server property.
 */
class AlgorithmSuiteWireShapeTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server algorithm-suite wire-shape plaintext".getBytes(StandardCharsets.UTF_8);

    /** Expected wire facts for one suite: 2-byte suite id, format version, signing bit. */
    record SuiteShape(ESDKAlgorithmSuiteId suite, int suiteId, int version, boolean signing) {
        boolean committing() {
            return version == 2;
        }

        ESDKCommitmentPolicy policy() {
            // Committing suites are legal under REQUIRE_*; non-committing suites only under
            // FORBID_ENCRYPT_ALLOW_DECRYPT.
            return committing()
                ? ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
                : ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;
        }

        int messageIdLength() {
            return version == 2 ? 32 : 16;
        }

        @Override
        public String toString() {
            return String.format("%s(0x%04X)", suite.getValue(), suiteId);
        }
    }

    /**
     * The complete suite matrix from {@code spec/framework/algorithm-suites.md}: numeric id,
     * message-format version, and signing bit for every suite the ESDK defines.
     */
    private static final List<SuiteShape> SUITES = List.of(
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF, 0x0014, 1, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_NO_KDF, 0x0046, 1, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, 0x0078, 1, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256, 0x0114, 1, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256, 0x0146, 1, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, 0x0178, 1, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, 0x0214, 1, true),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, 0x0346, 1, true),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, 0x0378, 1, true),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, 0x0478, 2, false),
        new SuiteShape(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, 0x0578, 2, true));

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            for (SuiteShape shape : SUITES) {
                cases.add(Arguments.of(target, shape));
            }
        }
        return cases;
    }

    /**
     * The single keyring the target supports (Raw-AES, else hierarchical), gated so the target is a
     * visible skip when it supports neither. Wire shape is keyring-independent, so the target runs
     * once, under this keyring.
     */
    private static ConformanceKeyring keyringFor(EndpointPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring;
    }

    @ParameterizedTest(name = "suiteWireShape[{1}] {0}")
    @MethodSource("cases")
    void encryptedMessageHasSuiteWireShape(LanguageServerTarget target, SuiteShape shape) {
        ESDKClientConfig config = keyringFor(new EndpointPair(target, target)).config(shape.policy());
        byte[] ciphertext = EsdkOps.encrypt(
            target.endpoint(), config, PLAINTEXT, Map.of(), shape.suite(), null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);

        assertEquals(shape.suiteId(), message.algorithmSuiteId,
            target + " " + shape + ": the header must declare the algorithm suite the caller requested");
        assertEquals(shape.version(), message.version,
            target + " " + shape + ": message-format version for this suite generation");
        assertEquals(shape.messageIdLength(), message.messageIdLength,
            target + " " + shape + ": message-id length for this format version");

        if (shape.version() == 1) {
            for (int i = 0; i < 4; i++) {
                assertEquals(0, message.bytes[message.reservedOffset + i],
                    target + " " + shape + ": V1 reserved field byte " + i + " must be zero");
            }
            assertEquals(EsdkMessage.IV_LEN, message.bytes[message.ivLengthOffset] & 0xFF,
                target + " " + shape + ": V1 IV-length byte must equal the suite IV length");
        }

        assertEquals(shape.signing(), message.footerOffset >= 0,
            target + " " + shape + ": a footer must be present exactly for signing suites");
        if (shape.signing()) {
            assertTrue(message.signatureLength > 0,
                target + " " + shape + ": a signing suite's footer must carry a non-empty signature");
        }
    }
}
