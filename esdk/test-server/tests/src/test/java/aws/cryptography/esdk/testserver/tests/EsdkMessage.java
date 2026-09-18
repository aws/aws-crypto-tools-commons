package aws.cryptography.esdk.testserver.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A minimal, read-only parser for the AWS Encryption SDK message format
 * ({@code spec/data-format/message.md}), used by the wire-format and tamper tests to
 * locate exact field offsets on the ciphertext bytes a test already holds. It parses
 * a framed V1 or V2 message: header body, header authentication, the body frames, and
 * (for signing suites) the footer.
 *
 * <p>The parser validates its own work: {@link #parse} walks the entire message and
 * requires that the bytes it accounts for span exactly the input length. A test that
 * relies on a field offset therefore fails loudly if this parser is wrong about the
 * layout, rather than silently tampering the wrong byte and passing for the wrong
 * reason.
 *
 * <p>Only the framed content type is handled (the ESDK never emits non-framed
 * messages). IV length is 12 and auth-tag length 16 for every supported suite; V2
 * committing suites carry 32 bytes of algorithm-suite data (the commitment value).
 */
final class EsdkMessage {

    static final int IV_LEN = 12;
    static final int TAG_LEN = 16;
    static final int V2_SUITE_DATA_LEN = 32;
    static final long END_FRAME_MARKER = 0xFFFFFFFFL;

    /** 2-byte algorithm-suite ids that include an ECDSA signature (message has a footer). */
    private static final Set<Integer> SIGNING_SUITE_IDS = Set.of(0x0214, 0x0346, 0x0378, 0x0578);
    /** 2-byte algorithm-suite ids that commit the key (V2 message format, 32-byte suite data). */
    private static final Set<Integer> COMMITTING_SUITE_IDS = Set.of(0x0478, 0x0578);

    /** One parsed body frame. {@code contentLengthOffset} is -1 for a regular frame. */
    record Frame(int frameOffset, int sequenceNumberOffset, int ivOffset, int contentLengthOffset,
                 int contentOffset, int contentLength, int tagOffset, int endOffset, boolean isFinal) {
    }

    final byte[] bytes;
    final int version;
    final int algorithmSuiteId;
    final boolean signing;
    final int suiteIdOffset;
    final int messageIdOffset;
    final int messageIdLength;
    final int aadLengthOffset;      // 2-byte key-value-pairs length field
    final int aadContentOffset;     // first byte after the 2-byte length field
    final int aadLength;            // value of the length field
    final int edkCountOffset;       // 2-byte encrypted-data-key count
    final int edkCount;
    final int contentTypeOffset;
    final int reservedOffset;       // V1 only, else -1
    final int ivLengthOffset;       // V1 only, else -1
    final int frameLengthOffset;
    final long frameLength;
    final int headerAuthTagOffset;
    final int bodyStart;
    final List<Frame> frames;
    final int footerOffset;         // -1 when the suite does not sign
    final int signatureLength;      // -1 when the suite does not sign

    private EsdkMessage(byte[] bytes, int version, int algorithmSuiteId, boolean signing,
                        int suiteIdOffset, int messageIdOffset, int messageIdLength,
                        int aadLengthOffset, int aadContentOffset, int aadLength, int edkCountOffset,
                        int edkCount, int contentTypeOffset, int reservedOffset, int ivLengthOffset,
                        int frameLengthOffset, long frameLength, int headerAuthTagOffset, int bodyStart,
                        List<Frame> frames, int footerOffset, int signatureLength) {
        this.bytes = bytes;
        this.version = version;
        this.algorithmSuiteId = algorithmSuiteId;
        this.signing = signing;
        this.suiteIdOffset = suiteIdOffset;
        this.messageIdOffset = messageIdOffset;
        this.messageIdLength = messageIdLength;
        this.aadLengthOffset = aadLengthOffset;
        this.aadContentOffset = aadContentOffset;
        this.aadLength = aadLength;
        this.edkCountOffset = edkCountOffset;
        this.edkCount = edkCount;
        this.contentTypeOffset = contentTypeOffset;
        this.reservedOffset = reservedOffset;
        this.ivLengthOffset = ivLengthOffset;
        this.frameLengthOffset = frameLengthOffset;
        this.frameLength = frameLength;
        this.headerAuthTagOffset = headerAuthTagOffset;
        this.bodyStart = bodyStart;
        this.frames = frames;
        this.footerOffset = footerOffset;
        this.signatureLength = signatureLength;
    }

    private static int u8(byte[] b, int i) {
        return b[i] & 0xFF;
    }

    private static int u16(byte[] b, int i) {
        return (u8(b, i) << 8) | u8(b, i + 1);
    }

    private static long u32(byte[] b, int i) {
        return ((long) u16(b, i) << 16) | u16(b, i + 2);
    }

    static boolean isSigning(int algorithmSuiteId) {
        return SIGNING_SUITE_IDS.contains(algorithmSuiteId);
    }

    /**
     * Parse {@code bytes} as a framed ESDK message, throwing {@link IllegalStateException}
     * if the layout does not add up (which surfaces a parser bug immediately in any test
     * that uses it).
     */
    static EsdkMessage parse(byte[] bytes) {
        int version = u8(bytes, 0);
        int suiteIdOffset;
        int messageIdOffset;
        int messageIdLength;
        int pos;
        if (version == 1) {
            suiteIdOffset = 2;               // version(1) type(1)
            messageIdOffset = 4;
            messageIdLength = 16;
            pos = 20;
        } else if (version == 2) {
            suiteIdOffset = 1;               // version(1)
            messageIdOffset = 3;
            messageIdLength = 32;
            pos = 35;
        } else {
            throw new IllegalStateException("unsupported message version byte: " + version);
        }
        int suiteId = u16(bytes, suiteIdOffset);

        int aadLengthOffset = pos;
        int aadLength = u16(bytes, pos);
        pos += 2;
        int aadContentOffset = pos;
        pos += aadLength;

        int edkCountOffset = pos;
        int edkCount = u16(bytes, pos);
        pos += 2;
        for (int i = 0; i < edkCount; i++) {
            int providerIdLen = u16(bytes, pos);
            pos += 2 + providerIdLen;
            int providerInfoLen = u16(bytes, pos);
            pos += 2 + providerInfoLen;
            int edkLen = u16(bytes, pos);
            pos += 2 + edkLen;
        }

        int contentTypeOffset = pos;
        int contentType = u8(bytes, pos);
        pos += 1;
        if (contentType != 2) {
            throw new IllegalStateException("expected framed content type (2), got " + contentType);
        }

        int reservedOffset = -1;
        int ivLengthOffset = -1;
        if (version == 1) {
            reservedOffset = pos;
            pos += 4;                        // reserved
            ivLengthOffset = pos;
            int ivLen = u8(bytes, pos);
            pos += 1;
            if (ivLen != IV_LEN) {
                throw new IllegalStateException("unexpected V1 IV length: " + ivLen);
            }
        }
        int frameLengthOffset = pos;
        long frameLength = u32(bytes, pos);
        pos += 4;
        if (version == 2) {
            pos += V2_SUITE_DATA_LEN;        // algorithm suite data (commit key)
        }
        // header authentication
        if (version == 1) {
            pos += IV_LEN;                   // header-auth IV (zeros)
        }
        int headerAuthTagOffset = pos;
        pos += TAG_LEN;
        int bodyStart = pos;

        List<Frame> frames = parseFrames(bytes, pos, frameLength);
        int bodyEnd = frames.get(frames.size() - 1).endOffset();

        boolean signing = isSigning(suiteId);
        int footerOffset = -1;
        int signatureLength = -1;
        int consumedEnd = bodyEnd;
        if (signing) {
            footerOffset = bodyEnd;
            signatureLength = u16(bytes, bodyEnd);
            consumedEnd = bodyEnd + 2 + signatureLength;
        }
        if (consumedEnd != bytes.length) {
            throw new IllegalStateException("parser did not consume the whole message: consumed "
                + consumedEnd + " of " + bytes.length + " bytes (version " + version + ", suite 0x"
                + Integer.toHexString(suiteId) + ")");
        }

        return new EsdkMessage(bytes, version, suiteId, signing, suiteIdOffset, messageIdOffset,
            messageIdLength, aadLengthOffset, aadContentOffset, aadLength, edkCountOffset, edkCount,
            contentTypeOffset, reservedOffset, ivLengthOffset, frameLengthOffset, frameLength,
            headerAuthTagOffset, bodyStart, frames, footerOffset, signatureLength);
    }

    private static List<Frame> parseFrames(byte[] b, int start, long frameLength) {
        List<Frame> frames = new ArrayList<>();
        int p = start;
        while (true) {
            long first4 = u32(b, p);
            if (first4 == END_FRAME_MARKER) {
                int seqOffset = p + 4;
                int ivOffset = seqOffset + 4;
                int contentLengthOffset = ivOffset + IV_LEN;
                int contentLength = (int) u32(b, contentLengthOffset);
                int contentOffset = contentLengthOffset + 4;
                int tagOffset = contentOffset + contentLength;
                int end = tagOffset + TAG_LEN;
                frames.add(new Frame(p, seqOffset, ivOffset, contentLengthOffset, contentOffset,
                    contentLength, tagOffset, end, true));
                return frames;
            }
            int ivOffset = p + 4;
            int contentOffset = ivOffset + IV_LEN;
            int tagOffset = contentOffset + (int) frameLength;
            int end = tagOffset + TAG_LEN;
            frames.add(new Frame(p, p, ivOffset, -1, contentOffset, (int) frameLength, tagOffset,
                end, false));
            p = end;
        }
    }
}
