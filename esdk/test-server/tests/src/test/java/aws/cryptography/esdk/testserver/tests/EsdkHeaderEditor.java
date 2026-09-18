package aws.cryptography.esdk.testserver.tests;

/**
 * Produces synthetically malformed messages from a real, valid one by rewriting the
 * encryption-context (header AAD) region in place. The edits keep the AAD length field
 * unchanged, so every downstream offset (EDKs, body, footer) stays valid and the message
 * is still walkable — only the encryption-context <em>contents</em> are made malformed, so
 * a conformant header deserializer must reject the message.
 *
 * <p>This is a targeted editor over a genuine message rather than a from-scratch serializer:
 * it reuses the real header authentication, EDKs, and body the server produced, and only
 * corrupts the specific structural field under test.
 *
 * <p>The header AAD key-value-pairs region (at {@link EsdkMessage#aadContentOffset}, spanning
 * {@link EsdkMessage#aadLength} bytes) is: a 2-byte pair count, then per pair a 2-byte key
 * length, the key, a 2-byte value length, and the value.
 */
final class EsdkHeaderEditor {

    private EsdkHeaderEditor() {
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    private static void putU16(byte[] b, int i, int value) {
        b[i] = (byte) (value >>> 8);
        b[i + 1] = (byte) value;
    }

    /** The offset of the 2-byte encryption-context pair-count field. */
    static int pairCountOffset(EsdkMessage message) {
        return message.aadContentOffset;
    }

    /** The offset of the first key's 2-byte length field. */
    static int firstKeyLengthOffset(EsdkMessage message) {
        return message.aadContentOffset + 2;
    }

    /** Overwrite the encryption-context pair count with {@code count}. */
    static byte[] withPairCount(EsdkMessage message, int count) {
        byte[] copy = message.bytes.clone();
        putU16(copy, pairCountOffset(message), count);
        return copy;
    }

    /** Overwrite the first key's length field with {@code keyLength}. */
    static byte[] withFirstKeyLength(EsdkMessage message, int keyLength) {
        byte[] copy = message.bytes.clone();
        putU16(copy, firstKeyLengthOffset(message), keyLength);
        return copy;
    }

    /** Overwrite the first byte of the first encryption-context key with {@code value}. */
    static byte[] withFirstKeyByte(EsdkMessage message, int value) {
        byte[] copy = message.bytes.clone();
        int firstKeyOffset = firstKeyLengthOffset(message) + 2;
        copy[firstKeyOffset] = (byte) value;
        return copy;
    }

    /**
     * Overwrite the second pair's key bytes with the first pair's key so the two keys are
     * equal (a duplicate key). Requires the two keys to be the same byte length; callers
     * arrange this by choosing an encryption context whose keys serialize to equal lengths.
     */
    static byte[] withDuplicateFirstKey(EsdkMessage message) {
        byte[] copy = message.bytes.clone();
        int pos = message.aadContentOffset;
        int pairCount = u16(copy, pos);
        pos += 2;
        if (pairCount < 2) {
            throw new IllegalStateException("need at least two encryption-context pairs to duplicate a key");
        }
        // First pair.
        int firstKeyLength = u16(copy, pos);
        pos += 2;
        int firstKeyOffset = pos;
        pos += firstKeyLength;
        int firstValueLength = u16(copy, pos);
        pos += 2 + firstValueLength;
        // Second pair's key.
        int secondKeyLength = u16(copy, pos);
        pos += 2;
        int secondKeyOffset = pos;
        if (secondKeyLength != firstKeyLength) {
            throw new IllegalStateException("duplicate-key edit requires equal-length keys: first="
                + firstKeyLength + " second=" + secondKeyLength);
        }
        System.arraycopy(copy, firstKeyOffset, copy, secondKeyOffset, firstKeyLength);
        return copy;
    }
}
