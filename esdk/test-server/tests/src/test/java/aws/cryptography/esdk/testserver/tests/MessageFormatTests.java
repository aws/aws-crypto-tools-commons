package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Positive wire-format conformance: encrypt a message, parse it with {@link EsdkMessage},
 * and assert the produced bytes match the message-format specification. These are
 * per-server properties (parsing is client-side and independent of any decrypt target),
 * so they run against every configured target. Catalog behaviors
 * (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>BODY-001</b> — a regular frame is sequence number ‖ IV ‖ content ‖ tag, content
 *       length equal to the frame length
 *       ({@code spec/data-format/message-body.md#regular-frame}).</li>
 *   <li><b>BODY-002 / BODY-003</b> — the body ends in exactly one final frame; per-frame
 *       content sums to the plaintext length
 *       ({@code spec/data-format/message-body.md#final-frame}).</li>
 *   <li><b>BODY-004</b> — the per-frame IV is the big-endian sequence number zero-padded to
 *       the IV length ({@code spec/data-format/message-body.md#regular-frame-iv}).</li>
 *   <li><b>BODY-008</b> — encrypt always writes the framed content type (0x02)
 *       ({@code spec/client-apis/encrypt.md#nonframed-message-body-encryption}).</li>
 *   <li><b>ENC-011</b> — empty plaintext produces exactly one (empty) final frame
 *       ({@code spec/client-apis/encrypt.md#construct-the-body}).</li>
 *   <li><b>ENC-015</b> — no bytes beyond the message format: the parse consumes the whole
 *       message ({@code spec/client-apis/encrypt.md#behavior}).</li>
 *   <li><b>ENC-016</b> — the header records the input frame length, or the 4096 default
 *       ({@code spec/client-apis/encrypt.md#frame-length}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). Uses a V2 committing, non-signing suite so the message ends at
 * the final frame (no footer), keeping the framing assertions deterministic.
 */
class MessageFormatTests {

    private static final ESDKClientConfig CONFIG =
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final long FRAME_LENGTH = 16L;

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    private static byte[] encrypt(LanguageServerTarget target, byte[] plaintext, Long frameLength) {
        return EsdkOps.encrypt(target.endpoint(), CONFIG, plaintext, Map.of(), SUITE, frameLength);
    }

    private static int u32(byte[] b, int i) {
        return ((b[i] & 0xFF) << 24) | ((b[i + 1] & 0xFF) << 16) | ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
    }

    /**
     * BODY-001 / BODY-004: every regular frame is seq ‖ IV ‖ content(frameLen) ‖ tag; the
     * per-frame IV is the zero-padded big-endian sequence number; sequence numbers start at
     * 1 and increment by 1.
     */
    @ParameterizedTest(name = "regularFrameStructure {0}")
    @MethodSource("targets")
    void regularFramesFollowSpec(LanguageServerTarget target) {
        byte[] plaintext = new byte[(int) (FRAME_LENGTH * 3 + 5)];  // 3 regular frames + a short final
        byte[] ciphertext = encrypt(target, plaintext, FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.frames.size() >= 2, target + ": expected multiple frames");

        for (int i = 0; i < message.frames.size(); i++) {
            EsdkMessage.Frame frame = message.frames.get(i);
            int expectedSeq = i + 1;
            assertEquals(expectedSeq, u32(ciphertext, frame.sequenceNumberOffset()),
                target + ": frame " + i + " sequence number must be " + expectedSeq);
            // BODY-004: IV = 8 zero bytes then the 4-byte big-endian sequence number.
            for (int z = 0; z < 8; z++) {
                assertEquals(0, ciphertext[frame.ivOffset() + z],
                    target + ": frame " + i + " IV high byte " + z + " must be zero");
            }
            assertEquals(expectedSeq, u32(ciphertext, frame.ivOffset() + 8),
                target + ": frame " + i + " IV low 4 bytes must be the big-endian sequence number");
            if (!frame.isFinal()) {
                assertEquals(FRAME_LENGTH, frame.contentLength(),
                    target + ": regular frame " + i + " content length must equal the frame length");
            }
        }
    }

    /** BODY-002 / BODY-003: the body ends in exactly one final frame; contents sum to the plaintext. */
    @ParameterizedTest(name = "exactlyOneFinalFrame {0}")
    @MethodSource("targets")
    void bodyEndsInExactlyOneFinalFrame(LanguageServerTarget target) {
        int plaintextLength = (int) (FRAME_LENGTH * 2 + 3);
        byte[] ciphertext = encrypt(target, new byte[plaintextLength], FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);

        long finalFrames = message.frames.stream().filter(EsdkMessage.Frame::isFinal).count();
        assertEquals(1, finalFrames, target + ": framed data must contain exactly one final frame");
        assertTrue(message.frames.get(message.frames.size() - 1).isFinal(),
            target + ": the final frame must be the last frame");
        int totalContent = message.frames.stream().mapToInt(EsdkMessage.Frame::contentLength).sum();
        assertEquals(plaintextLength, totalContent,
            target + ": per-frame content lengths must sum to the plaintext length");
    }

    /** ENC-011: empty plaintext produces exactly one final frame carrying zero content bytes. */
    @ParameterizedTest(name = "emptyPlaintextSingleFinalFrame {0}")
    @MethodSource("targets")
    void emptyPlaintextProducesEmptyFinalFrame(LanguageServerTarget target) {
        byte[] ciphertext = encrypt(target, new byte[0], FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(1, message.frames.size(), target + ": empty plaintext must produce exactly one frame");
        assertTrue(message.frames.get(0).isFinal(), target + ": the single frame must be a final frame");
        assertEquals(0, message.frames.get(0).contentLength(),
            target + ": the empty-plaintext final frame must carry zero content bytes");
    }

    /** BODY-008 / ENC-015: encrypt writes the framed content type and no bytes beyond the format. */
    @ParameterizedTest(name = "framedAndNoExtraData {0}")
    @MethodSource("targets")
    void encryptWritesFramedContentTypeAndNoExtraData(LanguageServerTarget target) {
        byte[] ciphertext = encrypt(target, "framed content-type check".getBytes(StandardCharsets.UTF_8),
            FRAME_LENGTH);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(0x02, ciphertext[message.contentTypeOffset] & 0xFF,
            target + ": content type must be framed (0x02)");
        // ENC-015: parse() already requires the message to be consumed exactly; assert the last
        // (final) frame ends precisely at the ciphertext end for this non-signing suite.
        assertEquals(ciphertext.length, message.frames.get(message.frames.size() - 1).endOffset(),
            target + ": a non-signing message must end exactly at its final frame (no extra data)");
    }

    /** ENC-016: the header records the input frame length, and the 4096 default when none is given. */
    @ParameterizedTest(name = "frameLengthRecorded {0}")
    @MethodSource("targets")
    void headerRecordsFrameLength(LanguageServerTarget target) {
        byte[] custom = encrypt(target, "frame length 512".getBytes(StandardCharsets.UTF_8), 512L);
        assertEquals(512L, EsdkMessage.parse(custom).frameLength,
            target + ": the header frame length must equal the input frame length (512)");

        byte[] dflt = encrypt(target, "default frame length".getBytes(StandardCharsets.UTF_8), null);
        assertEquals(4096L, EsdkMessage.parse(dflt).frameLength,
            target + ": with no input frame length the header must record the 4096 default");
    }
}
