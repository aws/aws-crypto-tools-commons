package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Interop for a frame length that is not a multiple of the cipher block size. The message format
 * permits any frame length in [1, 2^32 - 1] ({@code spec/client-apis/encrypt.md#frame-length}),
 * and a reader that pads or rounds frame strides to the AES block size mis-parses every regular
 * frame after the first — a suspicion recorded in ESDK-Java's own history, which rejected
 * non-16-multiple frame sizes, relaxed the check, restored it over compatibility concerns, and
 * finally removed it.
 *
 * <p>An encryptor is permitted to restrict which frame lengths it offers (the suite's
 * frame-length variance decision), so an encrypt-side rejection aborts the combination as a
 * visible skip. Once a message exists, decrypting it is not optional: every reader must parse
 * the 999-byte frame stride exactly.
 *
 * <p>Frame-length parsing is keyring-independent, so each pair runs once under the keyring both
 * endpoints support ({@link ConformanceKeyring}): Raw-AES where available, otherwise the
 * hierarchical keyring, the one the native Rust ESDK supports.
 */
class FrameLengthInteropTests {

    private static final long ODD_FRAME_LENGTH = 999;

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
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

    @ParameterizedTest(name = "oddFrameLengthInterop {0}")
    @MethodSource("pairs")
    void nonBlockMultipleFrameLengthInteroperates(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] plaintext = new byte[(int) (2 * ODD_FRAME_LENGTH + 501)];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i * 31);
        }

        byte[] ciphertext;
        try {
            ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, plaintext, Map.of(),
                null, ODD_FRAME_LENGTH);
        } catch (ESDKClientError implementationRestriction) {
            // Encrypt-side frame-length restrictions are implementation-permitted and are not
            // asserted as cross-language conformance; only the produced message's decode is.
            Assumptions.abort("encryptor restricts frame length " + ODD_FRAME_LENGTH + " ("
                + pair.encryptTarget() + "): " + implementationRestriction.getMessage());
            return;
        }

        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(ODD_FRAME_LENGTH, message.frameLength,
            pair + ": the header must carry the requested frame length");
        assertEquals(3, message.frames.size(),
            pair + ": 2 full frames plus a final frame");
        for (int i = 0; i < 2; i++) {
            EsdkMessage.Frame frame = message.frames.get(i);
            assertTrue(!frame.isFinal(),
                pair + ": frame " + i + " must be a regular frame");
            assertEquals(ODD_FRAME_LENGTH,
                (long) (frame.tagOffset() - frame.contentOffset()),
                pair + ": regular frame " + i + " must carry exactly the frame length of content");
        }
        EsdkMessage.Frame finalFrame = message.frames.get(2);
        assertTrue(finalFrame.isFinal(), pair + ": the last frame must be the final frame");
        assertEquals(501, finalFrame.contentLength(),
            pair + ": the final frame must carry the remainder");

        assertArrayEquals(plaintext, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
            pair + ": every reader must decode the non-block-multiple frame stride exactly");
    }
}
