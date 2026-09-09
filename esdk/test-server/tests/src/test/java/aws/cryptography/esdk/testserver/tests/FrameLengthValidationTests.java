package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Frame-length input-validation conformance on encrypt (a per-server property). Catalog
 * behavior (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>ENC-001</b> — encrypt rejects a frame length that is not greater than 0. The spec
 *       requires the frame length to be greater than 0 and at most 2^32-1
 *       ({@code spec/client-apis/encrypt.md#frame-length}).</li>
 * </ul>
 *
 * <p>Only the {@code > 0} bound is asserted here because it is the spec requirement common to
 * every implementation. The "multiple of the cipher block size" restriction and the signed-int
 * (2^31-1) cap are implementation-specific — the message format permits any frame length up to
 * 2^32-1, and the native implementations accept the full range — so they are not asserted as
 * cross-language conformance.
 *
 * <p>Frame-length validation is keyring-independent, so each target runs once under the keyring it
 * supports ({@link ConformanceKeyring}): Raw-AES where available, otherwise the hierarchical
 * keyring, the one the native Rust ESDK supports. A rejected frame length surfaces as a modeled
 * {@link ESDKClientError}.
 */
class FrameLengthValidationTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server frame-length-validation plaintext".getBytes(StandardCharsets.UTF_8);

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
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

    /** ENC-001: a frame length that is not greater than 0 (here negative) is rejected on encrypt. */
    @ParameterizedTest(name = "nonPositiveFrameLengthRejected {0}")
    @MethodSource("targets")
    void encryptRejectsNonPositiveFrameLength(LanguageServerTarget target) {
        ESDKClientConfig config = configFor(new EndpointPair(target, target));
        KnownBugGate.gate("encrypt-non-positive-frame-length-generic-error", target.language(),
            () -> assertThrows(ESDKClientError.class,
                () -> EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(), null, -16L),
                "encrypt with a frame length that is not greater than 0 must be rejected as an "
                    + "ESDKClientError (" + target + ")"));
    }
}
