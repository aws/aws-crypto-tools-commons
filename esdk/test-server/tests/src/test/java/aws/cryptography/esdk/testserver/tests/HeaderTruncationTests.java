package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Incomplete-header rejection (HDR-025): decrypt must reject a message whose header is not fully
 * present ({@code spec/client-apis/decrypt.md#parse-the-header}). Covers a zero-byte input, a
 * version-only single byte, and a message truncated in the middle of the header (before the body
 * begins). Asserts only the decryptor's validation, so it runs decrypt-side: the reference
 * implementation produces the message and every configured target decrypts it
 * ({@link ReferenceImplementation#decryptSide}). Fully offline (Raw-AES). Rejections
 * surface as a modeled {@link ESDKClientError}.
 */
class HeaderTruncationTests {

    private static final Set<String> FEATURES = Set.of("raw-aes");

    private static final byte[] PLAINTEXT =
        "esdk-test-server header-truncation plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKClientConfig CONFIG = EsdkClientConfigs.rawAes();

    static List<ReferencePair> decryptSide() {
        return ReferenceImplementation.decryptSide(FEATURES);
    }

    /** HDR-025: an empty (zero-byte) message is rejected. */
    @ParameterizedTest(name = "zeroByteRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsZeroByteMessage(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), CONFIG, new byte[0]),
            "decrypt of a zero-byte message must be rejected (" + pair + ")");
    }

    /** HDR-025: a single (version-only) byte is rejected. */
    @ParameterizedTest(name = "versionOnlyByteRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsVersionOnlyByte(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), CONFIG, PLAINTEXT);
        byte[] versionOnly = Arrays.copyOf(ciphertext, 1);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), CONFIG, versionOnly),
            "decrypt of a single version byte must be rejected (" + pair + ")");
    }

    /** HDR-025: a message truncated in the middle of the header (before the body) is rejected. */
    @ParameterizedTest(name = "truncatedHeaderRejected {0}")
    @MethodSource("decryptSide")
    void decryptRejectsTruncatedHeader(ReferencePair pair) {
        FeatureGate.require(FEATURES, pair.asEndpointPair());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), CONFIG, PLAINTEXT, Map.of(), null, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        // Truncate one byte before the body begins — the header is incomplete.
        byte[] truncatedHeader = Arrays.copyOf(ciphertext, message.bodyStart - 1);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), CONFIG, truncatedHeader),
            "decrypt of a message truncated mid-header must be rejected (" + pair + ")");
    }
}
