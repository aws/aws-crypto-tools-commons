package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Incomplete-header rejection (HDR-025): decrypt must reject a message whose header is not fully
 * present ({@code spec/client-apis/decrypt.md#parse-the-header}). Covers a zero-byte input, a
 * version-only single byte, and a message truncated in the middle of the header (before the body
 * begins). Cross-language pairwise matrix. Incomplete-header rejection is keyring-independent, so
 * each pair runs once under the keyring both endpoints support (Raw-AES where available, else the
 * hierarchical keyring the native Rust ESDK supports). Rejections surface as a modeled
 * {@link ESDKClientError}.
 */
class HeaderTruncationTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server header-truncation plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

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

    /** HDR-025: an empty (zero-byte) message is rejected. */
    @ParameterizedTest(name = "zeroByteRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsZeroByteMessage(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, new byte[0]),
            "decrypt of a zero-byte message must be rejected (" + pair + ")");
    }

    /** HDR-025: a single (version-only) byte is rejected. */
    @ParameterizedTest(name = "versionOnlyByteRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsVersionOnlyByte(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT);
        byte[] versionOnly = Arrays.copyOf(ciphertext, 1);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, versionOnly),
            "decrypt of a single version byte must be rejected (" + pair + ")");
    }

    /** HDR-025: a message truncated in the middle of the header (before the body) is rejected. */
    @ParameterizedTest(name = "truncatedHeaderRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsTruncatedHeader(EndpointPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, Map.of(), null, null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        // Truncate one byte before the body begins — the header is incomplete.
        byte[] truncatedHeader = Arrays.copyOf(ciphertext, message.bodyStart - 1);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, truncatedHeader),
            "decrypt of a message truncated mid-header must be rejected (" + pair + ")");
    }
}
