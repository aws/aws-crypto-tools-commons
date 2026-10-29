package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.util.function.Supplier;

/**
 * Runs a streamed-decrypt assertion under {@link #BUG} when the ciphertext is a
 * multi-frame message with a signing suite, the only messages the bug affects.
 * Any other ciphertext runs the assertion ungated.
 */
final class SignedStreamDecryptGate {

    static final String BUG = "stream-decrypt-rejects-multi-frame-signed-message";

    private SignedStreamDecryptGate() {
    }

    /**
     * Stream-decrypt {@code ciphertext} with {@code decryptStream}, assert it recovers
     * {@code expected}, and return the recovered plaintext.
     */
    static byte[] decryptStream(TargetPair pair, byte[] ciphertext, byte[] expected,
                                Supplier<byte[]> decryptStream, String message) {
        EsdkMessage parsed = EsdkMessage.parse(ciphertext);
        if (!parsed.signing || parsed.frames.size() < 2) {
            byte[] recovered = decryptStream.get();
            assertArrayEquals(expected, recovered, message);
            return recovered;
        }
        byte[][] recovered = new byte[1][];
        KnownBugGate.gateDeclared(BUG, pair.decryptTarget(), () -> {
            try {
                recovered[0] = decryptStream.get();
            } catch (ESDKClientError e) {
                throw new AssertionError("streamed decrypt failed: " + e.getMessage(), e);
            }
            assertArrayEquals(expected, recovered[0], message);
        });
        return recovered[0];
    }
}
