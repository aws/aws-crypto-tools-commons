package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Live cross-language byte-flip mutation fuzz. Each run the encrypt endpoint produces a fresh
 * committing, signing message under the keyring both endpoints share ({@link ConformanceKeyring},
 * so the native Rust ESDK participates via the hierarchical keyring); the decrypt endpoint then
 * flips one random byte and decrypts, asserting the mutation-fuzz oracle ({@link MutationFuzz}):
 * decrypt never crashes and never returns altered plaintext.
 *
 * <p>Non-deterministic by design — over runs it explores fresh plaintexts, IVs and byte positions
 * that the fixed {@link KatMutationFuzzTests} corpus does not. A violation reports the base-message
 * hex and the flipped index, so the case can be promoted into the fixed corpus.
 */
class DifferentialMutationFuzzTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server differential mutation-fuzz plaintext".getBytes(StandardCharsets.UTF_8);
    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /**
     * A fresh message from the encrypt endpoint, with one random byte flipped, is either rejected
     * with a modeled error or accepted with the original plaintext on the decrypt endpoint — never
     * a crash, never altered plaintext.
     */
    @ParameterizedTest(name = "randomByteFlipHandledCleanly {0}")
    @MethodSource("pairs")
    void randomByteFlipHandledCleanly(EndpointPair pair) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(pair);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + pair);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), pair);
        ESDKClientConfig config = keyring.config(POLICY);

        byte[] message =
            EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT, Map.of(), SUITE, null);
        assertArrayEquals(PLAINTEXT, EsdkOps.decrypt(pair.decryptEndpoint(), config, message),
            "baseline: the untampered message must decrypt (" + pair + ")");

        int index = ThreadLocalRandom.current().nextInt(message.length);
        byte[] mutated = message.clone();
        mutated[index] ^= (byte) 0xFF;
        MutationFuzz.Outcome outcome =
            MutationFuzz.decryptCapturing(pair.decryptEndpoint(), config, mutated);
        String failure = MutationFuzz.checkOracle(message, index, PLAINTEXT, outcome);
        assertNull(failure,
            () -> pair + ": " + failure + "\nbase message (" + message.length + " bytes) hex="
                + MutationFuzz.hex(message));
    }
}
