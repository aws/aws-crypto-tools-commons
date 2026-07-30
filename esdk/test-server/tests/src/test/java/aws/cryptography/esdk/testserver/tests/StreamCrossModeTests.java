package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /** STREAM-002: one-shot encrypt, streamed decrypt round-trips. */
    @ParameterizedTest(name = "oneShotEncryptStreamDecrypt {0}")
    @MethodSource("pairs")
    void oneShotEncryptDecryptsUnderStreaming(EndpointPair pair) {
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
    void streamedEncryptDecryptsOneShot(EndpointPair pair) {
        FeatureGate.require(Set.of("streaming"), pair);
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encryptStream(pair.encryptEndpoint(), config, PLAINTEXT);
        byte[] recovered = EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "one-shot decrypt of a streamed-encrypted message must recover the plaintext (" + pair + ")");
    }
}
