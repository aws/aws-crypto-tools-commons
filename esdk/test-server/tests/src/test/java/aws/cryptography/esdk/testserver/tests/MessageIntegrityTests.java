package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureGate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Whole-message integrity conformance: a well-formed message decrypts, but a message
 * that has been truncated or has trailing bytes appended is rejected. These need no
 * wire-format parser — they mutate the message as an opaque blob — so they are the
 * simplest of the tamper family. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>TAMPER-002</b> — decrypt rejects a message truncated by one byte
 *       ({@code spec/client-apis/decrypt.md#behavior}).</li>
 *   <li><b>DEC-006</b> — decrypt rejects a valid message followed by trailing bytes
 *       ({@code spec/client-apis/decrypt.md#behavior}).</li>
 * </ul>
 *
 * <p>Run over the cross-language pairwise matrix and a representative suite set (a
 * committing suite and a committing+signing suite, so both the "ends at the final
 * frame" and "ends at the footer" message shapes are covered). Whole-message integrity is
 * keyring-independent, so each pair runs once under the keyring both endpoints support
 * ({@link ConformanceKeyring}): Raw-AES where available, else the hierarchical keyring the native
 * Rust ESDK supports. ESDK-originated failures surface as {@link ESDKClientError}.
 */
class MessageIntegrityTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server message-integrity plaintext, long enough to span a frame or two"
            .getBytes(StandardCharsets.UTF_8);

    /** Committing (final frame is the last thing) and committing+signing (footer is last). */
    private static final List<ESDKAlgorithmSuiteId> SUITES = List.of(
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384);

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (TargetPair pair : LanguageServerRegistry.shared().pairs()) {
            for (ESDKAlgorithmSuiteId suite : SUITES) {
                cases.add(Arguments.of(pair, suite));
            }
        }
        return cases;
    }

    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    /**
     * The single keyring both endpoints support (Raw-AES, else hierarchical), gated so the pair is
     * a visible skip when they share none. Resolved before producing a message.
     */
    private static ESDKClientConfig configFor(TargetPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        return keyring.config(POLICY);
    }

    /** TAMPER-002: dropping the final byte of a message makes decrypt fail. */
    @ParameterizedTest(name = "truncateByOneRejected[{1}] {0}")
    @MethodSource("cases")
    void decryptRejectsTruncatedMessage(TargetPair pair, ESDKAlgorithmSuiteId suite) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT,
            java.util.Map.of(), suite, null);
        // Baseline: the untampered message round-trips, so the rejection below is
        // attributable to the truncation alone.
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
            "baseline: untampered message must decrypt (" + pair + ", " + suite.getValue() + ")");

        byte[] truncated = Arrays.copyOf(ciphertext, ciphertext.length - 1);
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, truncated),
            "decrypt of a message truncated by one byte must be rejected as an ESDKClientError ("
                + pair + ", " + suite.getValue() + ")");
    }

    /** DEC-006: appending trailing bytes after a valid message makes decrypt fail. */
    @ParameterizedTest(name = "trailingBytesRejected[{1}] {0}")
    @MethodSource("cases")
    void decryptRejectsTrailingBytes(TargetPair pair, ESDKAlgorithmSuiteId suite) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT,
            java.util.Map.of(), suite, null);

        byte[] withTrailer = Arrays.copyOf(ciphertext, ciphertext.length + 4);
        withTrailer[ciphertext.length] = (byte) 0xDE;
        withTrailer[ciphertext.length + 1] = (byte) 0xAD;
        withTrailer[ciphertext.length + 2] = (byte) 0xBE;
        withTrailer[ciphertext.length + 3] = (byte) 0xEF;
        // The trailing-bytes bug is suite-variant-specific, so the ledger holds one entry per suite.
        String bugId = ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.equals(suite)
            ? "decrypt-accepts-trailing-bytes-commit-key"
            : "decrypt-accepts-trailing-bytes-commit-key-ecdsa";
        KnownBugGate.gate(bugId, pair.decryptTarget().language(),
            () -> assertThrows(ESDKClientError.class,
                () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, withTrailer),
                "decrypt of a valid message with 4 trailing bytes appended must be rejected as an "
                    + "ESDKClientError (" + pair + ", " + suite.getValue() + ")"));
    }
}
