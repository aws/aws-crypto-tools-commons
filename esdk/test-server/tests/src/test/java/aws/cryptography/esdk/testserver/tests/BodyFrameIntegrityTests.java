package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Whole-frame body integrity. The framed body is a sequence of frames, each sealed with
 * AES-GCM over additional authenticated data that binds the message id, the frame's
 * sequence number, and its content length
 * ({@code spec/data-format/message-body-aad.md}); the frame IV is the sequence number
 * ({@code spec/client-apis/encrypt.md#construct-a-frame}); and the body ends in exactly
 * one final frame ({@code spec/data-format/message-body.md}). Moving, dropping, or
 * duplicating a whole frame therefore lands a frame at a position it was not sealed for,
 * splicing a frame from another message hits a different message id and derived key, and
 * truncating at a frame boundary leaves no final frame. Decrypt MUST reject all of these
 * ({@code spec/client-apis/decrypt.md#decrypt-the-message-body}).
 *
 * <p>Because each frame is sealed for its own position and message, these rejections do
 * not depend on whether an implementation reads the on-wire sequence-number field or
 * reconstructs it from a counter: the relocated frame's IV, AAD, and (for a splice) key
 * no longer match, so authentication fails regardless. This is the frame-as-a-unit
 * attack surface; the existing tamper tests corrupt bytes within a frame, none manipulate
 * frames as units. Added by gap analysis; not a catalog behavior.
 *
 * <p>Uses a committing, non-signing suite (0x0478) so a rejection is attributable to the
 * body frames alone: there is no footer, and the header commitment is left intact. The
 * plaintext spans three whole regular frames plus a short final frame, giving adjacent
 * equal-length regular frames to manipulate. Frame integrity is keyring-independent, so
 * each pair runs once under the keyring both endpoints support ({@link ConformanceKeyring}):
 * Raw-AES where available, otherwise the hierarchical keyring, the one the native Rust ESDK
 * supports. ESDK-originated failures surface as {@link ESDKClientError}.
 */
class BodyFrameIntegrityTests {

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final long FRAME_LENGTH = 512L;
    private static final byte[] PLAINTEXT = deterministicPlaintext(3 * (int) FRAME_LENGTH + 100);

    private static byte[] deterministicPlaintext(int length) {
        byte[] plaintext = new byte[length];
        for (int i = 0; i < length; i++) {
            plaintext[i] = (byte) (i % 251);
        }
        return plaintext;
    }

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /**
     * The single keyring both endpoints support (Raw-AES, else hierarchical), gated so the pair is
     * a visible skip when they share none. Resolved before producing a message.
     */
    private static ESDKClientConfig configFor(EndpointPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring.config(POLICY);
    }

    private static byte[] encrypt(EndpointPair pair, ESDKClientConfig config) {
        return EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, Map.of(), SUITE, FRAME_LENGTH);
    }

    /**
     * Parse a freshly produced message, confirm it round-trips (so a later rejection is the
     * surgery's doing), and return its regular (non-final) frames.
     */
    private static List<EsdkMessage.Frame> regularFrames(
            byte[] ciphertext, EndpointPair pair, ESDKClientConfig config) {
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
            "baseline: the untampered multi-frame message must decrypt (" + pair + ")");
        List<EsdkMessage.Frame> regular = message.frames.stream().filter(f -> !f.isFinal()).toList();
        assertTrue(regular.size() >= 2,
            "baseline: expected at least two regular frames to manipulate (" + pair + ")");
        return regular;
    }

    private static void assertRejected(
            EndpointPair pair, ESDKClientConfig config, byte[] tampered, String what) {
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, tampered),
            "decrypt must reject " + what + " (" + pair + ")");
    }

    private static byte[] frameBytes(byte[] ciphertext, EsdkMessage.Frame frame) {
        return Arrays.copyOfRange(ciphertext, frame.frameOffset(), frame.endOffset());
    }

    /** Two adjacent regular frames swapped: each sits at a sequence/IV it was not sealed for. */
    @ParameterizedTest(name = "swappedFramesRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsSwappedFrames(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = encrypt(pair, config);
        List<EsdkMessage.Frame> regular = regularFrames(ciphertext, pair, config);
        EsdkMessage.Frame first = regular.get(0);
        EsdkMessage.Frame second = regular.get(1);
        assertEquals(first.endOffset() - first.frameOffset(), second.endOffset() - second.frameOffset(),
            "baseline: adjacent regular frames must be the same length (" + pair + ")");
        byte[] tampered = ciphertext.clone();
        System.arraycopy(frameBytes(ciphertext, second), 0, tampered, first.frameOffset(),
            second.endOffset() - second.frameOffset());
        System.arraycopy(frameBytes(ciphertext, first), 0, tampered, second.frameOffset(),
            first.endOffset() - first.frameOffset());
        assertRejected(pair, config, tampered, "a body with two regular frames swapped");
    }

    /** A middle regular frame deleted: the following frame moves onto the wrong sequence number. */
    @ParameterizedTest(name = "deletedFrameRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsDeletedFrame(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = encrypt(pair, config);
        List<EsdkMessage.Frame> regular = regularFrames(ciphertext, pair, config);
        EsdkMessage.Frame victim = regular.get(1);
        int victimLength = victim.endOffset() - victim.frameOffset();
        byte[] tampered = new byte[ciphertext.length - victimLength];
        System.arraycopy(ciphertext, 0, tampered, 0, victim.frameOffset());
        System.arraycopy(ciphertext, victim.endOffset(), tampered, victim.frameOffset(),
            ciphertext.length - victim.endOffset());
        assertRejected(pair, config, tampered, "a body with a regular frame deleted");
    }

    /** A regular frame duplicated: the replayed copy lands on the next frame's sequence number. */
    @ParameterizedTest(name = "duplicatedFrameRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsDuplicatedFrame(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = encrypt(pair, config);
        List<EsdkMessage.Frame> regular = regularFrames(ciphertext, pair, config);
        EsdkMessage.Frame frame = regular.get(0);
        byte[] block = frameBytes(ciphertext, frame);
        byte[] tampered = new byte[ciphertext.length + block.length];
        System.arraycopy(ciphertext, 0, tampered, 0, frame.endOffset());
        System.arraycopy(block, 0, tampered, frame.endOffset(), block.length);
        System.arraycopy(ciphertext, frame.endOffset(), tampered, frame.endOffset() + block.length,
            ciphertext.length - frame.endOffset());
        assertRejected(pair, config, tampered, "a body with a regular frame duplicated");
    }

    /** A body cut at a regular-frame boundary never reaches a final frame. */
    @ParameterizedTest(name = "missingFinalFrameRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsBodyTruncatedBeforeFinalFrame(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = encrypt(pair, config);
        List<EsdkMessage.Frame> regular = regularFrames(ciphertext, pair, config);
        EsdkMessage.Frame lastRegular = regular.get(regular.size() - 1);
        byte[] tampered = Arrays.copyOf(ciphertext, lastRegular.endOffset());
        assertRejected(pair, config, tampered, "a body truncated at a frame boundary with no final frame");
    }

    /** A frame transplanted from another message hits a different message id and derived key. */
    @ParameterizedTest(name = "crossMessageSplicedFrameRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsFrameSplicedFromAnotherMessage(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] messageA = encrypt(pair, config);
        byte[] messageB = encrypt(pair, config);
        List<EsdkMessage.Frame> regularA = regularFrames(messageA, pair, config);
        List<EsdkMessage.Frame> regularB =
            EsdkMessage.parse(messageB).frames.stream().filter(f -> !f.isFinal()).toList();
        EsdkMessage.Frame target = regularA.get(1);
        EsdkMessage.Frame source = regularB.get(1);
        assertEquals(target.frameOffset(), source.frameOffset(),
            "baseline: the two messages must share frame offsets (" + pair + ")");
        assertEquals(target.endOffset() - target.frameOffset(), source.endOffset() - source.frameOffset(),
            "baseline: the spliced frame must be the same length (" + pair + ")");
        byte[] tampered = messageA.clone();
        System.arraycopy(messageB, source.frameOffset(), tampered, target.frameOffset(),
            source.endOffset() - source.frameOffset());
        assertRejected(pair, config, tampered, "a body with a frame spliced from another message");
    }
}
