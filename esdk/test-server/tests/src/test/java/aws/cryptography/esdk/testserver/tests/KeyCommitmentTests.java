package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Key-commitment coverage Tests: the interaction of the three ESDK commitment
 * policies with the full set of supported algorithm suites, on BOTH the encrypt
 * and decrypt legs.
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
 * id contains {@code COMMIT_KEY}): two committing suites
 * ({@code ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY} and its ECDSA variant) and nine
 * non-committing suites. These Tests enumerate the full set so that a new
 * {@code Language_Server} added later must reproduce the same
 * success/failure behavior across every suite and policy to pass.
 *
 * <p>All executions are fully offline: a Raw-AES keyring / Default CMM over the
 * in-process Java {@code Language_Server}, driven by the one generated Java
 * {@code Test_Client} over the real rpcv2Cbor hop. A policy violation originates
 * inside the ESDK and therefore surfaces as a modeled {@link ESDKClientError}
 * (Requirements 4.10, 5.6), never a bare HTTP error.
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

    private static EndpointPair pair;

    @BeforeAll
    static void bootEndpoints() {
        pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime());
    }

    @AfterAll
    static void shutdownEndpoints() {
        if (pair != null) {
            pair.close();
        }
    }

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
    // Test A: encrypt honors the commitment policy across the full suite set.
    // -----------------------------------------------------------------------

    /**
     * One case per (commitment policy × algorithm suite): encrypting with an
     * explicit suite succeeds iff the suite's commitment matches the policy's
     * encrypt constraint, otherwise the ESDK rejects it as an {@link
     * ESDKClientError}.
     */
    record EncryptCase(ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite, boolean expectSuccess) {
        @Override
        public String toString() {
            return policy.getValue() + " / " + suite.getValue()
                + " -> " + (expectSuccess ? "success" : "reject");
        }
    }

    static List<EncryptCase> encryptCases() {
        List<EncryptCase> cases = new ArrayList<>();
        for (ESDKCommitmentPolicy policy : POLICIES) {
            for (ESDKAlgorithmSuiteId suite : ESDKAlgorithmSuiteId.values()) {
                cases.add(new EncryptCase(policy, suite, encryptAllowed(policy, suite)));
            }
        }
        return cases;
    }

    @ParameterizedTest(name = "encrypt[{0}]")
    @MethodSource("encryptCases")
    void encryptHonorsCommitmentPolicy(EncryptCase testCase) {
        if (testCase.expectSuccess()) {
            byte[] ciphertext = encrypt(testCase.policy(), testCase.suite(), PLAINTEXT);
            assertTrue(ciphertext.length > 0,
                "encrypt with an allowed suite must produce ciphertext (" + testCase + ")");
        } else {
            assertThrows(ESDKClientError.class,
                () -> encrypt(testCase.policy(), testCase.suite(), PLAINTEXT),
                "encrypt with a suite forbidden by the commitment policy must be rejected "
                    + "as an ESDKClientError (" + testCase + ")");
        }
    }

    // -----------------------------------------------------------------------
    // Test B: round-trip within a single policy for every allowed suite.
    // -----------------------------------------------------------------------

    static List<EncryptCase> roundTripCases() {
        List<EncryptCase> cases = new ArrayList<>();
        for (EncryptCase c : encryptCases()) {
            // Every suite allowed on encrypt under a policy is also allowed on
            // decrypt under that SAME policy (the encrypt constraint is the
            // stricter one), so it must round-trip byte-for-byte.
            if (c.expectSuccess()) {
                cases.add(c);
            }
        }
        return cases;
    }

    @ParameterizedTest(name = "roundTrip[{0}]")
    @MethodSource("roundTripCases")
    void roundTripWithinPolicy(EncryptCase testCase) {
        byte[] ciphertext = encrypt(testCase.policy(), testCase.suite(), PLAINTEXT);
        byte[] recovered = decrypt(testCase.policy(), ciphertext);
        assertArrayEquals(PLAINTEXT, recovered,
            "decrypt(encrypt(x)) must equal x under a single commitment policy (" + testCase + ")");
    }

    // -----------------------------------------------------------------------
    // Test C: decrypt honors the commitment policy across policies.
    // -----------------------------------------------------------------------

    /**
     * One case per (message commitment × decrypt policy): decrypting a message of
     * a given commitment property under a policy succeeds unless the policy
     * requires commitment on decrypt and the message is non-committing.
     */
    record DecryptCase(boolean messageCommitting, ESDKCommitmentPolicy decryptPolicy, boolean expectSuccess) {
        @Override
        public String toString() {
            return (messageCommitting ? "committing" : "nonCommitting") + " message / "
                + decryptPolicy.getValue() + " -> " + (expectSuccess ? "success" : "reject");
        }
    }

    static List<DecryptCase> decryptCases() {
        List<DecryptCase> cases = new ArrayList<>();
        for (boolean messageCommitting : new boolean[] {false, true}) {
            for (ESDKCommitmentPolicy policy : POLICIES) {
                cases.add(new DecryptCase(messageCommitting, policy,
                    decryptAllowed(policy, messageCommitting)));
            }
        }
        return cases;
    }

    @ParameterizedTest(name = "decrypt[{0}]")
    @MethodSource("decryptCases")
    void decryptHonorsCommitmentPolicy(DecryptCase testCase) {
        // Produce a message of the requested commitment property with a policy
        // that permits it on encrypt: a committing message via
        // REQUIRE_ENCRYPT_ALLOW_DECRYPT, a non-committing message via
        // FORBID_ENCRYPT_ALLOW_DECRYPT.
        byte[] ciphertext = testCase.messageCommitting()
            ? encrypt(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT, COMMITTING_SUITE, PLAINTEXT)
            : encrypt(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, NON_COMMITTING_SUITE, PLAINTEXT);

        if (testCase.expectSuccess()) {
            byte[] recovered = decrypt(testCase.decryptPolicy(), ciphertext);
            assertArrayEquals(PLAINTEXT, recovered,
                "decrypt must recover the plaintext when the policy permits the message's "
                    + "commitment (" + testCase + ")");
        } else {
            assertThrows(ESDKClientError.class,
                () -> decrypt(testCase.decryptPolicy(), ciphertext),
                "decrypt of a non-committing message under REQUIRE_ENCRYPT_REQUIRE_DECRYPT must "
                    + "be rejected as an ESDKClientError (" + testCase + ")");
        }
    }

    // -----------------------------------------------------------------------
    // Harness helpers: single-leg encrypt / decrypt over the one Test_Client.
    // -----------------------------------------------------------------------

    /** CreateClient with the policy, then Encrypt {@code plaintext} with {@code suite}. */
    private static byte[] encrypt(ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite, byte[] plaintext) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(pair.encryptEndpoint());
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

    /** CreateClient with the policy, then Decrypt {@code ciphertext} (suite derives from the header). */
    private static byte[] decrypt(ESDKCommitmentPolicy policy, byte[] ciphertext) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(pair.decryptEndpoint());
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
