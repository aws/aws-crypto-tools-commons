package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Frame-length input-validation conformance on encrypt (a per-server property). Catalog
 * behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>ENC-001</b> — encrypt rejects a negative frame length
 *       ({@code spec/client-apis/encrypt.md#frame-length}).</li>
 *   <li><b>ENC-002</b> — encrypt rejects a frame length that is not a multiple of the cipher
 *       block size ({@code spec/client-apis/encrypt.md#frame-length}).</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES). A rejected frame length surfaces as a modeled
 * {@link ESDKClientError}.
 */
class FrameLengthValidationTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server frame-length-validation plaintext".getBytes(StandardCharsets.UTF_8);

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /** ENC-001: a negative frame length is rejected on encrypt. */
    @ParameterizedTest(name = "negativeFrameLengthRejected {0}")
    @MethodSource("targets")
    void encryptRejectsNegativeFrameLength(LanguageServerTarget target) {
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), null, -16L),
            "encrypt with a negative frame length must be rejected as an ESDKClientError (" + target + ")");
    }

    /** ENC-002: a frame length that is not a multiple of the 16-byte block size is rejected. */
    @ParameterizedTest(name = "nonBlockMultipleFrameLengthRejected {0}")
    @MethodSource("targets")
    void encryptRejectsNonBlockMultipleFrameLength(LanguageServerTarget target) {
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), null, 30L),
            "encrypt with a frame length that is not a multiple of the block size must be rejected "
                + "as an ESDKClientError (" + target + ")");
    }

    /** ENC-003: a frame length above 2^31-1 is rejected (the on-wire frame length is a UInt32,
     * but implementations cap it at the signed-int maximum). */
    @ParameterizedTest(name = "oversizedFrameLengthRejected {0}")
    @MethodSource("targets")
    void encryptRejectsOversizedFrameLength(LanguageServerTarget target) {
        ESDKClientConfig config = EsdkClientConfigs.rawAes();
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), null, 1L << 31),
            "encrypt with a frame length above 2^31-1 must be rejected as an ESDKClientError ("
                + target + ")");
    }
}
