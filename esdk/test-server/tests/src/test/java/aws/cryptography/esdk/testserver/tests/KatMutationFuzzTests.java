package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Exhaustive byte-flip mutation fuzz over a fixed known-answer message. One committing, signing
 * message is produced per keyring source; every byte of it is then flipped in turn and decrypted
 * on every language that supports the source, asserting the mutation-fuzz oracle
 * ({@link MutationFuzz}): decrypt never crashes and never returns altered plaintext. A committing
 * signing suite puts the header commitment value and authentication tag, the per-frame tag, and
 * the footer signature all in flip range, so a flip anywhere in the message is integrity-protected.
 *
 * <p>Two sources, so both keyring families are covered: Raw-AES (offline, the languages that
 * declare it) and the hierarchical keyring (the native Rust ESDK's only declared keyring). The
 * message is generated once per source at first use rather than committed as a fixed resource:
 * the only committed vectors are 10 KiB — too large to flip exhaustively across the matrix — and a
 * raw keyring's random message id and frame IV make offline byte-for-byte reproduction impossible.
 * A violating byte index is reported with the full base-message hex, so any finding is reproducible.
 */
class KatMutationFuzzTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server mutation-fuzz known-answer message".getBytes(StandardCharsets.UTF_8);
    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;

    /** One generated known-answer message per source, produced on first use and reused. */
    private static final Map<ConformanceKeyring, byte[]> KAT = new ConcurrentHashMap<>();

    /** A source keyring paired with one language that decrypts its flipped known-answer message. */
    record Case(ConformanceKeyring source, LanguageServerTarget target) {
        @Override
        public String toString() {
            return source + " -> " + target;
        }
    }

    static List<Arguments> cases() {
        FeatureDeclarations declarations = FeatureDeclarations.shared();
        List<Arguments> cases = new ArrayList<>();
        for (ConformanceKeyring source : ConformanceKeyring.values()) {
            for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
                if (supports(declarations, target, source)) {
                    cases.add(Arguments.of(new Case(source, target)));
                }
            }
        }
        return cases;
    }

    /**
     * Every single-byte flip of the source's known-answer message is either rejected with a
     * modeled error or accepted with the original plaintext — never a crash, never altered
     * plaintext.
     */
    @ParameterizedTest(name = "everyByteFlipHandledCleanly {0}")
    @MethodSource("cases")
    void everyByteFlipHandledCleanly(Case testCase) {
        ESDKClientConfig config = testCase.source().config(POLICY);
        byte[] message = katFor(testCase.source(), config);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(testCase.target().endpoint(), config, message),
            "baseline: the untampered known-answer message must decrypt on " + testCase.target());

        List<String> failures = new ArrayList<>();
        for (int i = 0; i < message.length; i++) {
            byte[] mutated = message.clone();
            mutated[i] ^= (byte) 0xFF;
            MutationFuzz.Outcome outcome =
                MutationFuzz.decryptCapturing(testCase.target().endpoint(), config, mutated);
            String failure = MutationFuzz.checkOracle(message, i, PLAINTEXT, outcome);
            if (failure != null) {
                failures.add(failure);
            }
        }
        assertTrue(failures.isEmpty(),
            () -> testCase + ": " + failures.size() + " byte flip(s) violated the oracle:\n"
                + String.join("\n", failures) + "\nbase message (" + message.length + " bytes) hex="
                + MutationFuzz.hex(message));
    }

    /** The source's known-answer message, produced once on the first target that supports it. */
    private static byte[] katFor(ConformanceKeyring source, ESDKClientConfig config) {
        return KAT.computeIfAbsent(source, s -> {
            FeatureDeclarations declarations = FeatureDeclarations.shared();
            URI generator = LanguageServerRegistry.shared().targets().stream()
                .filter(t -> supports(declarations, t, s))
                .map(LanguageServerTarget::endpoint)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("no language supports " + s));
            return EsdkOps.encrypt(generator, config, PLAINTEXT, Map.of(), SUITE, null);
        });
    }

    private static boolean supports(
            FeatureDeclarations declarations, LanguageServerTarget target, ConformanceKeyring source) {
        return source.features().stream().allMatch(f -> declarations.isSupported(target.language(), f));
    }
}
