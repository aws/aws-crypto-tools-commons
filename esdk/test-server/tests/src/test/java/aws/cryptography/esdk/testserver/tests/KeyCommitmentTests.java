package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Key-commitment conformance Tests: the interaction of the three ESDK commitment
 * policies with the full set of supported algorithm suites, on BOTH the encrypt
 * and decrypt legs, across the configured Language_Server targets.
 *
 * <p>Key commitment binds a ciphertext to exactly one data key. The ESDK exposes
 * three commitment policies, each constraining which algorithm suites may be used
 * and whether commitment is enforced on decrypt:
 * <ul>
 *   <li>{@code FORBID_ENCRYPT_ALLOW_DECRYPT} — encrypt MUST use a
 *       <em>non-committing</em> suite; decrypt accepts committing and
 *       non-committing messages.</li>
 *   <li>{@code REQUIRE_ENCRYPT_ALLOW_DECRYPT} — encrypt MUST use a
 *       <em>committing</em> suite; decrypt accepts committing and non-committing
 *       messages.</li>
 *   <li>{@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT} — encrypt MUST use a
 *       <em>committing</em> suite; decrypt MUST be given a <em>committing</em>
 *       message (a non-committing message is rejected).</li>
 * </ul>
 *
 * <p>The algorithm-suite set is split by whether the suite commits the key (its
 * id contains {@code COMMIT_KEY}): two committing suites and nine non-committing.
 * The Tests enumerate the full set across targets so a new {@code Language_Server}
 * must reproduce the same success/failure behavior to pass:
 * <ul>
 *   <li><b>Encrypt enforcement</b> is a per-server property, so it runs against
 *       <em>every target</em> ({@link LanguageServerRegistry#targets()}).</li>
 *   <li><b>Round-trip within a policy</b> and <b>decrypt enforcement</b> run over
 *       the full cross-language <em>pairwise matrix</em>
 *       ({@link LanguageServerRegistry#pairs()}) — encrypt on one target, decrypt
 *       on another — so commitment behavior is validated cross-language too.</li>
 * </ul>
 *
 * <p>All executions are fully offline (Raw-AES keyring / Default CMM). A policy
 * violation originates inside the ESDK and surfaces as a modeled
 * {@link ESDKClientError} (Requirements 4.10, 5.6), never a bare HTTP error.
 */
class KeyCommitmentTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server key-commitment plaintext".getBytes(StandardCharsets.UTF_8);

    /** A representative committing, NON-signing suite for the decrypt-side matrix. */
    private static final ESDKAlgorithmSuiteId COMMITTING_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    /** A representative non-committing, NON-signing suite for the decrypt-side matrix. */
    private static final ESDKAlgorithmSuiteId NON_COMMITTING_SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    private static final List<ESDKCommitmentPolicy> POLICIES = List.of(
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

    // -----------------------------------------------------------------------
    // Commitment model (the expected behavior every server must reproduce).
    // -----------------------------------------------------------------------

    /** A committing suite carries {@code COMMIT_KEY} in its id. */
    private static boolean isCommitting(ESDKAlgorithmSuiteId suite) {
        return suite.getValue().contains("COMMIT_KEY");
    }

    /** REQUIRE_ENCRYPT_* requires a committing suite on encrypt; FORBID_ENCRYPT_* forbids one. */
    private static boolean encryptAllowed(ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite) {
        boolean requiresCommittingOnEncrypt = policy.getValue().startsWith("REQUIRE_ENCRYPT");
        return requiresCommittingOnEncrypt == isCommitting(suite);
    }

    /** Only REQUIRE_ENCRYPT_REQUIRE_DECRYPT rejects a non-committing message on decrypt. */
    private static boolean decryptAllowed(ESDKCommitmentPolicy policy, boolean messageCommitting) {
        boolean requiresCommittingOnDecrypt =
            policy.equals(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
        return !requiresCommittingOnDecrypt || messageCommitting;
    }

    // -----------------------------------------------------------------------
    // Test A: encrypt honors the commitment policy across the full suite set,
    // on every target (encrypt enforcement is a per-server property).
    // -----------------------------------------------------------------------

    /** One case per (commitment policy × algorithm suite). */
    record EncryptCase(ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite, boolean expectSuccess) {
        @Override
        public String toString() {
            return policy.getValue() + " / " + suite.getValue()
                + " -> " + (expectSuccess ? "success" : "reject");
        }
    }

    private static List<EncryptCase> encryptCaseList() {
        List<EncryptCase> cases = new ArrayList<>();
        for (ESDKCommitmentPolicy policy : POLICIES) {
            for (ESDKAlgorithmSuiteId suite : ESDKAlgorithmSuiteId.values()) {
                cases.add(new EncryptCase(policy, suite, encryptAllowed(policy, suite)));
            }
        }
        return cases;
    }

    static List<Arguments> encryptTargetCases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            for (EncryptCase c : encryptCaseList()) {
                cases.add(Arguments.of(target, c));
            }
        }
        return cases;
    }

    @ParameterizedTest(name = "encrypt[{1}] {0}")
    @MethodSource("encryptTargetCases")
    void encryptHonorsCommitmentPolicy(LanguageServerTarget target, EncryptCase testCase) {
        if (testCase.expectSuccess()) {
            byte[] ciphertext = encrypt(target.endpoint(), testCase.policy(), testCase.suite(), PLAINTEXT);
            assertTrue(ciphertext.length > 0,
                "encrypt with an allowed suite must produce ciphertext (" + target + ", " + testCase + ")");
        } else {
            assertThrows(ESDKClientError.class,
                () -> encrypt(target.endpoint(), testCase.policy(), testCase.suite(), PLAINTEXT),
                "encrypt with a suite forbidden by the commitment policy must be rejected "
                    + "as an ESDKClientError (" + target + ", " + testCase + ")");
        }
    }

    // -----------------------------------------------------------------------
    // Test B: round-trip within a single policy for every allowed suite, over
    // the cross-language pairwise matrix.
    // -----------------------------------------------------------------------

    static List<Arguments> roundTripPairCases() {
        List<Arguments> cases = new ArrayList<>();
        for (EndpointPair pair : LanguageServerRegistry.shared().pairs()) {
            for (EncryptCase c : encryptCaseList()) {
                // Every suite allowed on encrypt under a policy is also allowed on
                // decrypt under that same policy, so it must round-trip.
                if (c.expectSuccess()) {
                    cases.add(Arguments.of(pair, c));
                }
            }
        }
        return cases;
    }

    @ParameterizedTest(name = "roundTrip[{1}] {0}")
    @MethodSource("roundTripPairCases")
    void roundTripWithinPolicy(EndpointPair pair, EncryptCase testCase) {
        byte[] ciphertext = encrypt(pair.encryptEndpoint(), testCase.policy(), testCase.suite(), PLAINTEXT);
        byte[] recovered = decrypt(pair.decryptEndpoint(), testCase.policy(), ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt(encrypt(x)) must equal x under a single commitment policy "
                + "(" + pair + ", " + testCase + ")");
    }

    // -----------------------------------------------------------------------
    // Test C: decrypt honors the commitment policy across policies, over the
    // cross-language pairwise matrix.
    // -----------------------------------------------------------------------

    /** One case per (message commitment × decrypt policy). */
    record DecryptCase(boolean messageCommitting, ESDKCommitmentPolicy decryptPolicy, boolean expectSuccess) {
        @Override
        public String toString() {
            return (messageCommitting ? "committing" : "nonCommitting") + " message / "
                + decryptPolicy.getValue() + " -> " + (expectSuccess ? "success" : "reject");
        }
    }

    private static List<DecryptCase> decryptCaseList() {
        List<DecryptCase> cases = new ArrayList<>();
        for (boolean messageCommitting : new boolean[] {false, true}) {
            for (ESDKCommitmentPolicy policy : POLICIES) {
                cases.add(new DecryptCase(messageCommitting, policy,
                    decryptAllowed(policy, messageCommitting)));
            }
        }
        return cases;
    }

    static List<Arguments> decryptPairCases() {
        List<Arguments> cases = new ArrayList<>();
        for (EndpointPair pair : LanguageServerRegistry.shared().pairs()) {
            for (DecryptCase c : decryptCaseList()) {
                cases.add(Arguments.of(pair, c));
            }
        }
        return cases;
    }

    @ParameterizedTest(name = "decrypt[{1}] {0}")
    @MethodSource("decryptPairCases")
    void decryptHonorsCommitmentPolicy(EndpointPair pair, DecryptCase testCase) {
        // Produce a message of the requested commitment property on the encrypt
        // endpoint with a policy that permits it: committing via
        // REQUIRE_ENCRYPT_ALLOW_DECRYPT, non-committing via FORBID_ENCRYPT_ALLOW_DECRYPT.
        byte[] ciphertext = testCase.messageCommitting()
            ? encrypt(pair.encryptEndpoint(), ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                COMMITTING_SUITE, PLAINTEXT)
            : encrypt(pair.encryptEndpoint(), ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
                NON_COMMITTING_SUITE, PLAINTEXT);

        if (testCase.expectSuccess()) {
            byte[] recovered = decrypt(pair.decryptEndpoint(), testCase.decryptPolicy(), ciphertext);
            assertArrayEquals(PLAINTEXT, recovered,
                "decrypt must recover the plaintext when the policy permits the message's "
                    + "commitment (" + pair + ", " + testCase + ")");
        } else {
            assertThrows(ESDKClientError.class,
                () -> decrypt(pair.decryptEndpoint(), testCase.decryptPolicy(), ciphertext),
                "decrypt of a non-committing message under REQUIRE_ENCRYPT_REQUIRE_DECRYPT must "
                    + "be rejected as an ESDKClientError (" + pair + ", " + testCase + ")");
        }
    }

    // -----------------------------------------------------------------------
    // Harness helpers: single-leg encrypt / decrypt over the one Test_Client.
    // -----------------------------------------------------------------------

    /** CreateClient with the policy on {@code endpoint}, then Encrypt with {@code suite}. */
    private static byte[] encrypt(URI endpoint, ESDKCommitmentPolicy policy,
                                  ESDKAlgorithmSuiteId suite, byte[] plaintext) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        String clientId = createClient(client, policy);
        ByteBuffer ciphertext = client.encrypt(
            EncryptInput.builder()
                .clientId(clientId)
                .plaintext(ByteBuffer.wrap(plaintext))
                .algorithmSuiteId(suite)
                .build())
            .getCiphertext();
        return toArray(ciphertext);
    }

    /** CreateClient with the policy on {@code endpoint}, then Decrypt {@code ciphertext}. */
    private static byte[] decrypt(URI endpoint, ESDKCommitmentPolicy policy, byte[] ciphertext) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        String clientId = createClient(client, policy);
        ByteBuffer plaintext = client.decrypt(
            DecryptInput.builder()
                .clientId(clientId)
                .ciphertext(ByteBuffer.wrap(ciphertext))
                .build())
            .getPlaintext();
        return toArray(plaintext);
    }

    private static String createClient(ESDKTestServerClient client, ESDKCommitmentPolicy policy) {
        return client.createClient(
            CreateClientInput.builder()
                .config(EsdkClientConfigs.rawAesWithCommitmentPolicy(policy))
                .build())
            .getClientId();
    }

    private static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
