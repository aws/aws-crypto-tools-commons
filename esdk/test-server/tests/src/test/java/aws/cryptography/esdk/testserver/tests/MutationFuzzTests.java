package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureDeclarations;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Byte-flip mutation fuzz. One committing, signing message per keyring source is produced by the
 * {@link DefaultProducer} (java by default, overridable); every language that supports the source
 * then flips each byte of that one message in turn and decrypts, asserting the mutation-fuzz
 * oracle ({@link MutationFuzz}): decrypt never crashes and never returns altered plaintext. One
 * producer, every byte, every decryptor — under a committing signing suite a single flipped byte
 * is caught by the header commitment value and authentication tag, a per-frame tag, or the footer
 * signature, all in flip range.
 *
 * <p>Two sources cover both keyring families: Raw-AES (offline; the default producer is java) and
 * the hierarchical keyring, which the native Rust ESDK decrypts and which the default producer
 * resolves to a hierarchical-capable language. The message is produced fresh per run rather than
 * committed as a fixed resource — the only committed vectors are 10 KiB (too large to flip
 * exhaustively across the matrix) and a raw keyring's random message id and frame IV make offline
 * byte-for-byte reproduction impossible — so a violating byte index is reported with the full
 * base-message hex, keeping any finding reproducible.
 */
class MutationFuzzTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server mutation-fuzz message".getBytes(StandardCharsets.UTF_8);
    private static final ESDKCommitmentPolicy POLICY =
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;

    /** One message per source, produced once by the default producer and reused by every decryptor. */
    private static final Map<ConformanceKeyring, byte[]> MESSAGE = new ConcurrentHashMap<>();

    /** A source keyring paired with one language that decrypts every flip of its message. */
    record Case(ConformanceKeyring source, LanguageServerTarget decryptor) {
        @Override
        public String toString() {
            return source + " -> " + decryptor;
        }
    }

    static List<Arguments> cases() {
        FeatureDeclarations declarations = FeatureDeclarations.shared();
        List<Arguments> cases = new ArrayList<>();
        for (ConformanceKeyring source : ConformanceKeyring.values()) {
            for (LanguageServerTarget decryptor : LanguageServerRegistry.shared().targets()) {
                if (supports(declarations, decryptor, source)) {
                    cases.add(Arguments.of(new Case(source, decryptor)));
                }
            }
        }
        return cases;
    }

    /**
     * Every single-byte flip of the source's message is either rejected with a modeled error or
     * accepted with the original plaintext on the decryptor — never a crash, never altered
     * plaintext.
     */
    @ParameterizedTest(name = "everyByteFlipHandledCleanly {0}")
    @MethodSource("cases")
    void everyByteFlipHandledCleanly(Case testCase) {
        ESDKClientConfig config = testCase.source().config(POLICY);
        byte[] message = messageFor(testCase.source(), config);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(testCase.decryptor().endpoint(), config, message),
            "baseline: the untampered message must decrypt on " + testCase.decryptor());

        List<String> failures = new ArrayList<>();
        for (int i = 0; i < message.length; i++) {
            byte[] mutated = message.clone();
            mutated[i] ^= (byte) 0xFF;
            MutationFuzz.Outcome outcome =
                MutationFuzz.decryptCapturing(testCase.decryptor().endpoint(), config, mutated);
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

    /** The source's message, produced once by the default producer for the source's Features. */
    private static byte[] messageFor(ConformanceKeyring source, ESDKClientConfig config) {
        return MESSAGE.computeIfAbsent(source, s ->
            EsdkOps.encrypt(DefaultProducer.producerFor(s.features()), config, PLAINTEXT, Map.of(),
                SUITE, null));
    }

    private static boolean supports(
            FeatureDeclarations declarations, LanguageServerTarget target, ConformanceKeyring source) {
        return source.features().stream().allMatch(f -> declarations.isSupported(
            target.language(), target.majorVersion(), target.repo(), f));
    }
}
