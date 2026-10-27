package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.PUBLIC_KEY_EC_KEY;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.bytes;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.createCmm;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.decrypt;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.decryptMaterials;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.encrypt;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.getEncryptionMaterials;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The Default CMM over a Raw AES keyring: GetEncryptionMaterials on the encrypt
 * target, DecryptMaterials on the decrypt target.
 *
 * <p>Ports the Default CMM vectors of the Dafny MPL test vectors
 * (AllDefaultCmm.dfy) that the model can express: the happy path, and the
 * reproduced-encryption-context success and failure sets. Adds one round trip
 * per ESDK algorithm suite and the commitment-policy rules the CMM enforces.
 */
public class DefaultCmmTest {

    private static final Set<String> FEATURES = Set.of("raw-aes", "default-cmm");

    /** The AllDefaultCmm.dfy root context: {a: a, b: b}. */
    private static final Map<String, String> ROOT_EC = Map.of("a", "a", "b", "b");

    /** A committing, non-signing suite, so the context gains no public key. */
    private static final AlgorithmSuiteId COMMIT_NO_SIGNING_SUITE =
        AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    // -----------------------------------------------------------------------
    // Algorithm suite properties
    // -----------------------------------------------------------------------

    static boolean isCommitting(AlgorithmSuiteId suite) {
        return suite.getValue().contains("COMMIT_KEY");
    }

    static boolean isSigning(AlgorithmSuiteId suite) {
        return suite.getValue().contains("ECDSA");
    }

    /** @return the data key length: the suite's AES key length. */
    static int dataKeyLength(AlgorithmSuiteId suite) {
        String id = suite.getValue();
        if (id.startsWith("ALG_AES_128")) return 16;
        if (id.startsWith("ALG_AES_192")) return 24;
        if (id.startsWith("ALG_AES_256")) return 32;
        throw new IllegalArgumentException("unknown suite " + id);
    }

    /** @return a policy the CMM accepts on encrypt for {@code suite}. */
    static CommitmentPolicy compatiblePolicy(AlgorithmSuiteId suite) {
        return isCommitting(suite)
            ? CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT
            : CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT;
    }

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    static Stream<Arguments> pairsBySuite() {
        return AlgorithmSuiteId.values().stream()
            .flatMap(suite -> pairs().stream().map(pair -> Arguments.of(suite, pair)));
    }

    // -----------------------------------------------------------------------
    // Round trips
    // -----------------------------------------------------------------------

    /** AllDefaultCmm.dfy "Simplest possible happy path": an empty context. */
    @ParameterizedTest(name = "[default-cmm] happy path, empty context {0}")
    @MethodSource("pairs")
    void happyPathEmptyContext(TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        AlgorithmSuiteId suite = AlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
        CommitmentPolicy policy = compatiblePolicy(suite);

        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), Map.of(), policy, suite);
        DecryptMaterialsOutput decrypted = decrypt(
            MplTestServerClients.forEndpoint(pair.decryptEndpoint()), encrypted, policy);

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(Map.of(), decrypted.getEncryptionContext());
    }

    @ParameterizedTest(name = "[default-cmm] round-trip {0} {1}")
    @MethodSource("pairsBySuite")
    void roundTripPerSuite(AlgorithmSuiteId suite, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        CommitmentPolicy policy = compatiblePolicy(suite);

        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), ROOT_EC, policy, suite);

        assertEquals(suite.getValue(), encrypted.getAlgorithmSuiteId().getValue());
        assertEquals(dataKeyLength(suite), encrypted.getPlaintextDataKey().remaining());
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        if (isSigning(suite)) {
            assertNotNull(encrypted.getSigningKey(), "a signing suite carries a signing key");
            assertTrue(encrypted.getEncryptionContext().containsKey(PUBLIC_KEY_EC_KEY),
                "a signing suite adds the verification key to the encryption context");
        } else {
            assertNull(encrypted.getSigningKey(), "a non-signing suite carries no signing key");
            assertEquals(ROOT_EC, encrypted.getEncryptionContext());
        }

        DecryptMaterialsOutput decrypted = decrypt(
            MplTestServerClients.forEndpoint(pair.decryptEndpoint()), encrypted, policy);

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(encrypted.getEncryptionContext(), decrypted.getEncryptionContext());
        if (isSigning(suite)) {
            assertNotNull(decrypted.getVerificationKey(), "a signing suite carries a verification key");
        } else {
            assertNull(decrypted.getVerificationKey(), "a non-signing suite carries no verification key");
        }
    }

    // -----------------------------------------------------------------------
    // Commitment policy
    // -----------------------------------------------------------------------

    /** The two REQUIRE_ENCRYPT policies' default suite, 05 78. */
    static Stream<Arguments> defaultSuites() {
        return targets().stream().flatMap(target -> Stream.of(
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, target),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, target)));
    }

    /** With no suite requested, the CMM picks its policy's default ESDK suite. */
    @ParameterizedTest(name = "[default-cmm] {0} defaults to {1} {2}")
    @MethodSource("defaultSuites")
    void defaultSuitePerPolicy(CommitmentPolicy policy, AlgorithmSuiteId expected,
            LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(target.endpoint()), ROOT_EC, policy, null);
        assertEquals(expected.getValue(), encrypted.getAlgorithmSuiteId().getValue());
    }

    /**
     * ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT defaults to
     * ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, as the Dafny MPL
     * (Defaults.dfy) returns. commitment-policy.md still says
     * ALG_AES_256_GCM_IV12_TAG16_NO_KDF; that text is out of date.
     */
    @ParameterizedTest(name = "[default-cmm] ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT default suite {0}")
    @MethodSource("targets")
    void forbidEncryptAllowDecryptDefaultSuite(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(target.endpoint()), ROOT_EC,
            CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT, null);
        KnownBugGate.gateDeclared("forbid-default-suite-no-kdf", target, () -> assertEquals(
            AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.getValue(),
            encrypted.getAlgorithmSuiteId().getValue()));
    }

    static Stream<Arguments> encryptRejections() {
        return targets().stream().flatMap(target -> Stream.of(
            Arguments.of(CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, target),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, target),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, target)));
    }

    @ParameterizedTest(name = "[default-cmm] {0} rejects encrypt with {1} {2}")
    @MethodSource("encryptRejections")
    void encryptRejectsSuiteOutsidePolicy(CommitmentPolicy policy, AlgorithmSuiteId suite,
            LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        MPLTestServerClient client = MplTestServerClients.forEndpoint(target.endpoint());
        String cmmId = createCmm(client);
        assertThrows(MPLClientError.class, () -> client.getEncryptionMaterials(
            getEncryptionMaterials(cmmId, ROOT_EC, policy, suite).build()));
    }

    static Stream<Arguments> decryptPolicies() {
        AlgorithmSuiteId nonCommitting = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        AlgorithmSuiteId committing = AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        return pairs().stream().flatMap(pair -> Stream.of(
            Arguments.of(nonCommitting, CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT, true, pair),
            Arguments.of(nonCommitting, CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT, true, pair),
            Arguments.of(nonCommitting, CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT, false, pair),
            Arguments.of(committing, CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT, true, pair)));
    }

    /**
     * Only REQUIRE_ENCRYPT_REQUIRE_DECRYPT refuses to decrypt a non-committing
     * suite; the two ALLOW_DECRYPT policies accept either kind.
     */
    @ParameterizedTest(name = "[default-cmm] decrypt {0} under {1}: allowed={2} {3}")
    @MethodSource("decryptPolicies")
    void decryptHonorsPolicy(AlgorithmSuiteId suite, CommitmentPolicy decryptPolicy, boolean allowed,
            TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), ROOT_EC,
            compatiblePolicy(suite), suite);
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());

        if (allowed) {
            DecryptMaterialsOutput decrypted = decrypt(dec, encrypted, decryptPolicy);
            assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        } else {
            String cmmId = createCmm(dec);
            assertThrows(MPLClientError.class, () -> dec.decryptMaterials(
                decryptMaterials(cmmId, encrypted, decryptPolicy).build()));
        }
    }

    // -----------------------------------------------------------------------
    // Reproduced encryption context
    // -----------------------------------------------------------------------

    /** Every subset of ROOT_EC, as in AllDefaultCmm.dfy's success set. */
    static Stream<Arguments> reproducedSubsets() {
        List<Map<String, String>> subsets = List.of(
            Map.of(), Map.of("a", "a"), Map.of("b", "b"), ROOT_EC);
        return pairs().stream()
            .flatMap(pair -> subsets.stream().map(subset -> Arguments.of(subset, pair)));
    }

    @ParameterizedTest(name = "[default-cmm] reproduced context {0} accepted {1}")
    @MethodSource("reproducedSubsets")
    void reproducedSubsetAccepted(Map<String, String> reproduced, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        CommitmentPolicy policy = compatiblePolicy(COMMIT_NO_SIGNING_SUITE);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), ROOT_EC, policy,
            COMMIT_NO_SIGNING_SUITE);
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        String cmmId = createCmm(dec);

        DecryptMaterialsOutput decrypted = MplTestServerClients.withRetry(() ->
            dec.decryptMaterials(decryptMaterials(cmmId, encrypted, policy)
                .reproducedEncryptionContext(reproduced)
                .build()));

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(ROOT_EC, decrypted.getEncryptionContext());
    }

    /**
     * AllDefaultCmm.dfy's failure set: a subset of ROOT_EC plus a non-empty
     * subset of the disjoint context {a: c, b: c, c: c}. A disagreeing value
     * fails the CMM's comparison; a key absent from the message is appended
     * to the context the keyring authenticates, so the unwrap fails.
     */
    static Stream<Arguments> reproducedMismatches() {
        List<Map<String, String>> mismatches = List.of(
            Map.of("a", "c"),
            Map.of("b", "c"),
            Map.of("c", "c"),
            Map.of("a", "a", "b", "c"),
            Map.of("a", "a", "b", "b", "c", "c"),
            Map.of("a", "c", "b", "c", "c", "c"));
        return pairs().stream()
            .flatMap(pair -> mismatches.stream().map(mismatch -> Arguments.of(mismatch, pair)));
    }

    @ParameterizedTest(name = "[default-cmm] reproduced context {0} rejected {1}")
    @MethodSource("reproducedMismatches")
    void reproducedMismatchRejected(Map<String, String> reproduced, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        CommitmentPolicy policy = compatiblePolicy(COMMIT_NO_SIGNING_SUITE);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), ROOT_EC, policy,
            COMMIT_NO_SIGNING_SUITE);
        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        String cmmId = createCmm(dec);

        assertThrows(MPLClientError.class, () -> dec.decryptMaterials(
            decryptMaterials(cmmId, encrypted, policy)
                .reproducedEncryptionContext(reproduced)
                .build()));
    }
}
