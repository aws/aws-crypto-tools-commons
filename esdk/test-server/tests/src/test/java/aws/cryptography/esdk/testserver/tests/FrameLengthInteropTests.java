package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.FrameLengthInputs;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
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
 * the frame stride exactly.
 *
 * <p>The test runs over the shared valid frame lengths, so 999 is one of several lengths,
 * next to block multiples such as 16 and 4096.
 *
 * <p>Frame-length parsing is keyring-independent, so each pair runs once under the keyring both
 * endpoints support ({@link ConformanceKeyring}): Raw-AES where available, otherwise the
 * hierarchical keyring, the one the native Rust ESDK supports.
 */
class FrameLengthInteropTests {

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    static Stream<Arguments> validFrameLengthsWithEachPair() {
        return ExampleCases.withEachPair(FrameLengthInputs.validFrameLengths());
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

    @ParameterizedTest(name = "oddFrameLengthInterop {0} {1}")
    @MethodSource("validFrameLengthsWithEachPair")
    void nonBlockMultipleFrameLengthInteroperates(Example<Long> example, TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        long frameLength = example.value();
        // Two full frames and then a remainder, such as 501 bytes for a frame length of 999.
        // When the remainder is shorter than the frame length, there is only one correct way to split
        // the plaintext into frames. For frame lengths 1 and 2 it is not shorter, so encrypt may
        // also write one more full frame and an empty final frame, and the checks below accept both.
        long remainder = Math.min((frameLength + 3) / 2, frameLength);
        byte[] plaintext = new byte[Math.toIntExact(2 * frameLength + remainder)];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i * 31);
        }

        byte[] ciphertext;
        try {
            ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, plaintext, Map.of(),
                null, frameLength);
        } catch (ESDKClientError implementationRestriction) {
            // Encrypt-side frame-length restrictions are implementation-permitted and are not
            // asserted as cross-language conformance; only the produced message's decode is.
            Assumptions.abort("encryptor restricts frame length " + frameLength + " ("
                + pair.encryptTarget() + "): " + implementationRestriction.getMessage());
            return;
        }

        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(frameLength, message.frameLength,
            pair + ": the header must carry the requested frame length");
        int regularFrames = message.frames.size() - 1;
        assertTrue(regularFrames >= 2, pair + ": at least 2 full frames plus a final frame");
        for (int i = 0; i < regularFrames; i++) {
            EsdkMessage.Frame frame = message.frames.get(i);
            assertTrue(!frame.isFinal(),
                pair + ": frame " + i + " must be a regular frame");
            assertEquals(frameLength,
                (long) (frame.tagOffset() - frame.contentOffset()),
                pair + ": regular frame " + i + " must carry exactly the frame length of content");
        }
        EsdkMessage.Frame finalFrame = message.frames.get(regularFrames);
        assertTrue(finalFrame.isFinal(), pair + ": the last frame must be the final frame");
        assertEquals(plaintext.length - regularFrames * frameLength, (long) finalFrame.contentLength(),
            pair + ": the final frame must carry the remainder");
        assertTrue(finalFrame.contentLength() <= frameLength,
            pair + ": the final frame must carry at most the frame length");

        assertArrayEquals(plaintext, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
            pair + ": every reader must decode the frame stride exactly");
    }
}
