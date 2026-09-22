package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-mode streaming interop (STREAM-002): one-shot encrypt interoperates with streamed
 * decrypt, and streamed encrypt interoperates with one-shot decrypt, over the cross-language
 * pairwise matrix ({@code spec/client-apis/streaming.md}).
 *
 * <p>Associated with the {@code streaming} Feature: {@link FeatureGate#require} is the first
 * statement so a combination whose language declares {@code streaming} unsupported is skipped
 * visibly before any server call. Fully offline (Raw-AES / Default CMM).
 */
class StreamCrossModeTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server cross-mode streaming plaintext, spanning more than one frame or so"
            .getBytes(StandardCharsets.UTF_8);

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /** STREAM-002: one-shot encrypt, streamed decrypt round-trips. */
    @ParameterizedTest(name = "oneShotEncryptStreamDecrypt {0}")
    @MethodSource("pairs")
    void oneShotEncryptDecryptsUnderStreaming(TargetPair pair) {
        FeatureGate.require(Set.of("streaming"), pair);
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT);
        byte[] recovered = EsdkOps.decryptStream(pair.decryptEndpoint(), config, ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "streamed decrypt of a one-shot-encrypted message must recover the plaintext (" + pair + ")");
    }

    /** STREAM-002: streamed encrypt, one-shot decrypt round-trips. */
    @ParameterizedTest(name = "streamEncryptOneShotDecrypt {0}")
    @MethodSource("pairs")
    void streamedEncryptDecryptsOneShot(TargetPair pair) {
        FeatureGate.require(Set.of("streaming"), pair);
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encryptStream(pair.encryptEndpoint(), config, PLAINTEXT);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "one-shot decrypt of a streamed-encrypted message must recover the plaintext (" + pair + ")");
    }

    /**
     * Streaming across a multi-frame body, byte-for-byte. A single-frame plaintext cannot
     * detect an implementation that assembles streamed frames wrongly — dropping, reordering,
     * or double-delivering whole frames while still succeeding. That failure mode shipped in
     * released ESDKs: the 2021 decrypt-node stream-assembly fix (a duplexed pipeline delivered
     * a subset of decrypted frames with no error) and the 2025 ESDK-Java offset-write fix
     * (streamed encrypt silently dropped plaintext bytes at frame-fill boundaries). Every
     * stream mode combination must reproduce the exact plaintext across several frames plus a
     * partial final frame ({@code spec/client-apis/streaming.md},
     * {@code spec/data-format/message-body.md#framed-data}).
     */
    @ParameterizedTest(name = "multiFrameStreamAssemblyExact {0}")
    @MethodSource("pairs")
    void multiFrameStreamingReproducesExactPlaintext(TargetPair pair) {
        FeatureGate.require(Set.of("streaming", "raw-aes"), pair);
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        long frameLength = 1024;
        byte[] plaintext = new byte[(int) (3 * frameLength + 100)];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) i;
        }

        byte[] streamed = EsdkOps.encryptStream(pair.encryptEndpoint(), config, plaintext,
            null, frameLength);
        assertArrayEquals(plaintext, EsdkOps.decrypt(pair.decryptEndpoint(), config, streamed),
            pair + ": one-shot decrypt of a multi-frame streamed-encrypted message must be exact");
        assertArrayEquals(plaintext, EsdkOps.decryptStream(pair.decryptEndpoint(), config, streamed),
            pair + ": streamed decrypt of a multi-frame streamed-encrypted message must be exact");

        byte[] oneShot = EsdkOps.encrypt(pair.encryptEndpoint(), config, plaintext, Map.of(),
            null, frameLength);
        assertArrayEquals(plaintext, EsdkOps.decryptStream(pair.decryptEndpoint(), config, oneShot),
            pair + ": streamed decrypt of a multi-frame one-shot message must be exact");
    }
}
