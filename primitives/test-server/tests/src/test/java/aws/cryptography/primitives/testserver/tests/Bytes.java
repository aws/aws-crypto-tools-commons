package aws.cryptography.primitives.testserver.tests;

import java.nio.ByteBuffer;
import java.util.HexFormat;

/** Byte helpers shared by the primitives Tests. */
final class Bytes {

    private static final HexFormat HEX = HexFormat.of();

    private Bytes() {
    }

    /** @return the bytes named by a lowercase hex string ("" is the empty array). */
    static byte[] hex(String hex) {
        return HEX.parseHex(hex);
    }

    /** @return {@code hex} wrapped for a Test_Client request. */
    static ByteBuffer buf(String hex) {
        return ByteBuffer.wrap(hex(hex));
    }

    /** @return a copy of the remaining bytes, without consuming {@code buffer}. */
    static byte[] of(ByteBuffer buffer) {
        ByteBuffer view = buffer.duplicate();
        byte[] out = new byte[view.remaining()];
        view.get(out);
        return out;
    }

    /** @return {@code bytes} with the bit 0x01 of byte {@code index} flipped. */
    static byte[] flip(byte[] bytes, int index) {
        byte[] out = bytes.clone();
        out[index] ^= 0x01;
        return out;
    }
}
