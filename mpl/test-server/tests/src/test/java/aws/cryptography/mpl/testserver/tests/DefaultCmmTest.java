package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.Cmm.PUBLIC_KEY_EC_KEY;
import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.provider.Arguments;

/**
 * The Default CMM over a Raw AES keyring: GetEncryptionMaterials on the encrypt
 * target, DecryptMaterials on the decrypt target.
 *
 * <p>Ports the Default CMM vectors of the Dafny MPL test vectors
 * (AllDefaultCmm.dfy) that the model can express: the happy path, and the
 * reproduced-encryption-context success and failure sets. Adds one round trip
 * per ESDK algorithm suite and the commitment-policy rules the CMM enforces.
 */
@KeyringFeature({"raw-aes", "default-cmm"})
public class DefaultCmmTest {

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

    static List<AlgorithmSuiteId> suites() {
        return List.copyOf(AlgorithmSuiteId.values());
    }

    // -----------------------------------------------------------------------
    // Round trips
    // -----------------------------------------------------------------------

    /** AllDefaultCmm.dfy "Simplest possible happy path": an empty context. */
    @KeyringTest(name = "[default-cmm] happy path, empty context {0}", pairs = true)
    void happyPathEmptyContext(Mpl encryptingMpl, Mpl decryptingMpl) {
        AlgorithmSuiteId suite = AlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
        CommitmentPolicy policy = compatiblePolicy(suite);

        GetEncryptionMaterialsOutput encrypted =
            encryptingMpl.defaultCmm().getEncryptionMaterials(Map.of(), policy, suite);
        DecryptMaterialsOutput decrypted = decryptingMpl.defaultCmm().decryptMaterials(encrypted, policy);

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(Map.of(), decrypted.getEncryptionContext());
    }

    @KeyringTest(
        name = "[default-cmm] round-trip {0} {1}",
        inputs = "suites",
        pairs = true)
    void roundTripPerSuite(AlgorithmSuiteId suite, Mpl encryptingMpl, Mpl decryptingMpl) {
        CommitmentPolicy policy = compatiblePolicy(suite);

        GetEncryptionMaterialsOutput encrypted =
            encryptingMpl.defaultCmm().getEncryptionMaterials(ROOT_EC, policy, suite);

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

        DecryptMaterialsOutput decrypted = decryptingMpl.defaultCmm().decryptMaterials(encrypted, policy);

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

    /**
     * Each policy's default ESDK suite: 03 78 for FORBID_ENCRYPT_ALLOW_DECRYPT,
     * 05 78 for the two REQUIRE_ENCRYPT policies. commitment-policy.md still
     * says ALG_AES_256_GCM_IV12_TAG16_NO_KDF for FORBID_ENCRYPT_ALLOW_DECRYPT;
     * that text is out of date.
     */
    static List<Arguments> defaultSuites() {
        return List.of(
            Arguments.of(CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384));
    }

    /** With no suite requested, the CMM picks its policy's default ESDK suite. */
    @KeyringTest(
        name = "[default-cmm] {0} defaults to {1} {2}",
        inputs = "defaultSuites")
    void defaultSuitePerPolicy(CommitmentPolicy policy, AlgorithmSuiteId expected, Mpl mpl) {
        GetEncryptionMaterialsOutput encrypted = mpl.defaultCmm().getEncryptionMaterials(ROOT_EC, policy, null);
        assertEquals(expected.getValue(), encrypted.getAlgorithmSuiteId().getValue());
    }

    static List<Arguments> encryptRejections() {
        return List.of(
            Arguments.of(CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256),
            Arguments.of(CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256));
    }

    @KeyringTest(
        name = "[default-cmm] {0} rejects encrypt with {1} {2}",
        inputs = "encryptRejections")
    void encryptRejectsSuiteOutsidePolicy(CommitmentPolicy policy, AlgorithmSuiteId suite, Mpl mpl) {
        mpl.defaultCmm().getEncryptionMaterialsFails(ROOT_EC, policy, suite);
    }

    static List<Arguments> decryptPolicies() {
        AlgorithmSuiteId nonCommitting = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        AlgorithmSuiteId committing = AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        return List.of(
            Arguments.of(nonCommitting, CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT, true),
            Arguments.of(nonCommitting, CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT, true),
            Arguments.of(nonCommitting, CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT, false),
            Arguments.of(committing, CommitmentPolicy.ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT, true));
    }

    /**
     * Only REQUIRE_ENCRYPT_REQUIRE_DECRYPT refuses to decrypt a non-committing
     * suite; the two ALLOW_DECRYPT policies accept either kind.
     */
    @KeyringTest(
        name = "[default-cmm] decrypt {0} under {1}: allowed={2} {3}",
        inputs = "decryptPolicies",
        pairs = true)
    void decryptHonorsPolicy(AlgorithmSuiteId suite, CommitmentPolicy decryptPolicy, boolean allowed,
            Mpl encryptingMpl, Mpl decryptingMpl) {
        GetEncryptionMaterialsOutput encrypted =
            encryptingMpl.defaultCmm().getEncryptionMaterials(ROOT_EC, compatiblePolicy(suite), suite);

        Cmm cmm = decryptingMpl.defaultCmm();
        if (allowed) {
            DecryptMaterialsOutput decrypted = cmm.decryptMaterials(encrypted, decryptPolicy);
            assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        } else {
            cmm.decryptMaterialsFails(cmm.decryptMaterialsRequest(encrypted, decryptPolicy));
        }
    }

    // -----------------------------------------------------------------------
    // Reproduced encryption context
    // -----------------------------------------------------------------------

    /** Every subset of ROOT_EC, as in AllDefaultCmm.dfy's success set. */
    static List<Map<String, String>> reproducedSubsets() {
        return List.of(Map.of(), Map.of("a", "a"), Map.of("b", "b"), ROOT_EC);
    }

    @KeyringTest(
        name = "[default-cmm] reproduced context {0} accepted {1}",
        inputs = "reproducedSubsets",
        pairs = true)
    void reproducedSubsetAccepted(Map<String, String> reproduced, Mpl encryptingMpl, Mpl decryptingMpl) {
        CommitmentPolicy policy = compatiblePolicy(COMMIT_NO_SIGNING_SUITE);
        GetEncryptionMaterialsOutput encrypted =
            encryptingMpl.defaultCmm().getEncryptionMaterials(ROOT_EC, policy, COMMIT_NO_SIGNING_SUITE);
        Cmm cmm = decryptingMpl.defaultCmm();

        DecryptMaterialsOutput decrypted = cmm.decryptMaterials(cmm.decryptMaterialsRequest(encrypted, policy)
            .reproducedEncryptionContext(reproduced));

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(ROOT_EC, decrypted.getEncryptionContext());
    }

    /**
     * AllDefaultCmm.dfy's failure set: a subset of ROOT_EC plus a non-empty
     * subset of the disjoint context {a: c, b: c, c: c}. A disagreeing value
     * fails the CMM's comparison; a key absent from the message is appended
     * to the context the keyring authenticates, so the unwrap fails.
     */
    static List<Map<String, String>> reproducedMismatches() {
        return List.of(
            Map.of("a", "c"),
            Map.of("b", "c"),
            Map.of("c", "c"),
            Map.of("a", "a", "b", "c"),
            Map.of("a", "a", "b", "b", "c", "c"),
            Map.of("a", "c", "b", "c", "c", "c"));
    }

    @KeyringTest(
        name = "[default-cmm] reproduced context {0} rejected {1}",
        inputs = "reproducedMismatches",
        pairs = true)
    void reproducedMismatchRejected(Map<String, String> reproduced, Mpl encryptingMpl, Mpl decryptingMpl) {
        CommitmentPolicy policy = compatiblePolicy(COMMIT_NO_SIGNING_SUITE);
        GetEncryptionMaterialsOutput encrypted =
            encryptingMpl.defaultCmm().getEncryptionMaterials(ROOT_EC, policy, COMMIT_NO_SIGNING_SUITE);
        Cmm cmm = decryptingMpl.defaultCmm();

        cmm.decryptMaterialsFails(cmm.decryptMaterialsRequest(encrypted, policy)
            .reproducedEncryptionContext(reproduced));
    }
}
