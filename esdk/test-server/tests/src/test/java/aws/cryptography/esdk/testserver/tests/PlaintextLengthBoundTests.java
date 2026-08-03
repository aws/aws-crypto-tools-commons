package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Plaintext-length-bound enforcement on streaming encrypt (ENC-007): if a plaintext-length
 * bound is provided, encrypt MUST NOT encrypt a plaintext longer than it
 * ({@code spec/client-apis/encrypt.md#plaintext-length-bound}). A per-server property.
 *
 * <p>Associated with the {@code streaming} Feature (the bound is a streaming-encrypt input):
 * {@link FeatureGate#require} is the first statement so a server that declares {@code streaming}
 * unsupported is skipped visibly. Fully offline (Raw-AES / Default CMM). A rejection surfaces as
 * a modeled {@link ESDKClientError}.
 */
class PlaintextLengthBoundTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server plaintext-length-bound plaintext, comfortably over sixteen bytes"
            .getBytes(StandardCharsets.UTF_8);

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /** A single-target pair so the streaming Feature gate can be evaluated. */
    private static EndpointPair samePair(LanguageServerTarget target) {
        return new EndpointPair(target, target);
    }

    /** ENC-007: streamed encrypt with a bound greater than or equal to the plaintext succeeds. */
    @ParameterizedTest(name = "boundAboveLengthSucceeds {0}")
    @MethodSource("targets")
    void encryptStreamSucceedsWithinBound(LanguageServerTarget target) {
        FeatureGate.require(Set.of("streaming"), samePair(target));
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        byte[] ciphertext = EsdkOps.encryptStream(target.endpoint(), config, PLAINTEXT,
            (long) PLAINTEXT.length);
        byte[] recovered = EsdkOps.decryptStream(target.endpoint(), config, ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "streamed encrypt with a bound equal to the plaintext length must round-trip (" + target + ")");
    }

    /** ENC-007: streamed encrypt of a plaintext longer than the bound is rejected. */
    @ParameterizedTest(name = "overBoundRejected {0}")
    @MethodSource("targets")
    void encryptStreamRejectsOverBoundPlaintext(LanguageServerTarget target) {
        FeatureGate.require(Set.of("streaming"), samePair(target));
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        long bound = PLAINTEXT.length - 1;
        KnownBugGate.gate("encrypt-stream-ignores-plaintext-length-bound", target.language(),
            () -> assertThrows(ESDKClientError.class,
                () -> EsdkOps.encryptStream(target.endpoint(), config, PLAINTEXT, bound),
                "streamed encrypt of a plaintext longer than the plaintext-length bound must be rejected "
                    + "as an ESDKClientError (" + target + ")"));
    }
}
