package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.EncryptedDataKeyInputs;
import aws.cryptography.testserver.tests.EncryptedDataKeyInputs.EdkMaximums;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Maximum-encrypted-data-keys enforcement across the configured Language_Server targets.
 * A multi-keyring of N raw-AES keyrings produces N EDKs, so a cap below N must be rejected and a
 * cap of N or more accepted. The fixed case is 2 EDKs with caps of 2 and 1.
 * Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>ENC-014</b> — encrypt rejects producing more EDKs than the configured maximum
 *       ({@code spec/client-apis/client.md#maximum-number-of-encrypted-data-keys}). Per-server
 *       property.</li>
 *   <li><b>DEC-002</b> — decrypt rejects a header carrying more EDKs than the configured
 *       maximum before unwrapping ({@code spec/client-apis/decrypt.md#v2-header-deserialization}).
 *       Decrypt-side rows; the decryptor holds the multi's generator keyring alone, so the cap
 *       is exercised on targets without multi-keyring support.</li>
 *   <li><b>HDR-019</b> — header parse enforces the maxEncryptedDataKeys bound: EDK counts at or
 *       below the max are accepted, counts above are rejected
 *       ({@code spec/data-format/message-header.md#encrypted-data-key-count}). Proven by the same
 *       N-EDK message that the DEC-002 case decrypts under a cap of N or more and rejects under a
 *       smaller cap.</li>
 * </ul>
 *
 * <p>Fully offline (Raw-AES multi-keyring / Default CMM). Rejections surface as a modeled
 * {@link ESDKClientError}.
 */
class MaxEncryptedDataKeysTests {

    /** Producing a message with 2 or more EDKs needs the multi-keyring. */
    private static final Set<String> FEATURES = Set.of("raw-aes", "multi");
    /** Decrypting it needs only the generator's single raw-AES keyring. */
    private static final Set<String> DECRYPTOR_FEATURES = Set.of("raw-aes");

    private static final byte[] PLAINTEXT =
        "esdk-test-server max-edk plaintext".getBytes(StandardCharsets.UTF_8);

    static Stream<Arguments> edkMaximumsWithEachLanguageServer() {
        return ExampleCases.withEachLanguageServer(EncryptedDataKeyInputs.edkMaximums());
    }

    /** One case per EDK count and decrypt-side pair: the arguments are (maximums, pair). */
    static Stream<Arguments> edkMaximumsWithEachDecryptSidePair() {
        List<ReferencePair> pairs = ReferenceImplementation.decryptSide(FEATURES);
        return EncryptedDataKeyInputs.edkMaximums().stream()
            .flatMap(maximums -> pairs.stream().map(pair -> Arguments.of(maximums, pair)));
    }

    /** ENC-014: encrypt with an N-EDK keyring succeeds at a cap of N or more but is rejected below N. */
    @ParameterizedTest(name = "encryptEnforcesMaxEdks {0} {1}")
    @MethodSource("edkMaximumsWithEachLanguageServer")
    void encryptEnforcesMaxEncryptedDataKeys(Example<EdkMaximums> example, LanguageServerTarget languageServer) {
        FeatureGate.require(FEATURES, new TargetPair(languageServer, languageServer));
        EdkMaximums maximums = example.value();
        int edkCount = maximums.edkCount();
        // A cap at or above the EDK count permits every EDK.
        byte[] ciphertext = EsdkOps.encrypt(languageServer.endpoint(),
            EsdkClientConfigs.rawAesMultiWithMaxEdks(edkCount, maximums.maximumThatAllows()), PLAINTEXT);
        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(languageServer.endpoint(), EsdkClientConfigs.rawAesMulti(), ciphertext),
            "a " + edkCount + "-EDK message under a cap of " + maximums.maximumThatAllows()
                + " must round-trip (" + languageServer + ")");
        // A cap below the EDK count forbids the EDKs past it.
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.encrypt(languageServer.endpoint(),
                EsdkClientConfigs.rawAesMultiWithMaxEdks(edkCount, maximums.maximumThatRejects()), PLAINTEXT),
            "encrypt producing " + edkCount + " EDKs under a max of " + maximums.maximumThatRejects()
                + " must be rejected (" + languageServer + ")");
    }

    /**
     * DEC-002 / HDR-019: an N-EDK message decrypts under a cap of N or more (count at/below the max
     * accepted) but is rejected under a cap below N (count above the max rejected, before any unwrap).
     * Decrypt-side: the reference produces the N-EDK message with the multi-keyring; every
     * raw-AES-capable target decrypts holding the generator keyring alone, so the cap is
     * exercised on targets without multi-keyring support.
     */
    @ParameterizedTest(name = "decryptEnforcesMaxEdks {0} {1}")
    @MethodSource("edkMaximumsWithEachDecryptSidePair")
    void decryptEnforcesMaxEncryptedDataKeys(Example<EdkMaximums> example, ReferencePair pair) {
        FeatureGate.require(FEATURES,
            new TargetPair(pair.encryptTarget(), pair.encryptTarget()));
        FeatureGate.require(DECRYPTOR_FEATURES,
            new TargetPair(pair.decryptTarget(), pair.decryptTarget()));
        EdkMaximums maximums = example.value();
        int edkCount = maximums.edkCount();
        // Encrypt an N-EDK message with no cap.
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), EsdkClientConfigs.rawAesMulti(edkCount),
            PLAINTEXT);

        assertArrayEquals(PLAINTEXT,
            EsdkOps.decrypt(pair.decryptEndpoint(),
                EsdkClientConfigs.rawAesWithMaxEdks(maximums.maximumThatAllows()), ciphertext),
            "a " + edkCount + "-EDK message must decrypt under a cap of " + maximums.maximumThatAllows()
                + " (" + pair + ")");
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(),
                EsdkClientConfigs.rawAesWithMaxEdks(maximums.maximumThatRejects()), ciphertext),
            "decrypt of a " + edkCount + "-EDK message under a max of " + maximums.maximumThatRejects()
                + " must be rejected (" + pair + ")");
    }
}
