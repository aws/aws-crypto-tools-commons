package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
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
 * Key-commitment <em>value</em> tamper conformance: the decrypt operation derives the commit key
 * from the plaintext data key and requires it to equal the 32-byte commitment stored in the V2
 * header's algorithm-suite-data field — so a message whose stored commitment is corrupted MUST be
 * rejected ({@code spec/client-apis/decrypt.md#verify-the-header}: "The derived commit key MUST
 * equal the commit key stored in the message header").
 *
 * <p>This is the commitment security property itself, distinct from the commitment-<em>policy</em>
 * conformance in {@code KeyCommitmentTests} (which never corrupts a message). The tamper flips one
 * byte of the algorithm-suite-data field at its parsed offset. Not a catalog behavior — added by
 * gap analysis against the spec (no source ESDK suite tampers the stored commitment on the wire).
 *
 * <p>Uses the committing non-signing suite so the only integrity layers are the commitment check
 * and header auth. The commitment field is keyring-independent, so each pair runs once under the
 * keyring both endpoints support ({@link ConformanceKeyring}): Raw-AES where available, else the
 * hierarchical keyring the native Rust ESDK supports. Rejections surface as a modeled
 * {@link ESDKClientError}.
 */
class KeyCommitmentTamperTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server commitment-tamper plaintext".getBytes(StandardCharsets.UTF_8);
    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

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

    /**
     * The V2 algorithm-suite-data (commitment) field sits between the 4-byte frame length and the
     * header auth tag: {@code frameLengthOffset + 4 .. headerAuthTagOffset}.
     */
    private static int suiteDataOffset(EsdkMessage message) {
        int offset = message.frameLengthOffset + 4;
        assertEquals(EsdkMessage.V2_SUITE_DATA_LEN, message.headerAuthTagOffset - offset,
            "baseline: the V2 suite-data field must span exactly 32 bytes");
        return offset;
    }

    /** Flipping a byte of the stored 32-byte commitment value makes decrypt fail. */
    @ParameterizedTest(name = "commitmentValueTamperRejected {0}")
    @MethodSource("pairs")
    void decryptRejectsTamperedCommitmentValue(TargetPair pair) {
        ESDKClientConfig config = configFor(pair);
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, Map.of(), SUITE,
            null);
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), config, ciphertext),
            "baseline: the untampered committing message must decrypt (" + pair + ")");
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertEquals(2, message.version, "baseline: a committing suite must produce a V2 message");
        byte[] tampered = ciphertext.clone();
        tampered[suiteDataOffset(message)] ^= (byte) 0xFF;
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, tampered),
            "decrypt of a message whose stored key-commitment value is corrupted must be rejected ("
                + pair + ")");
    }
}
