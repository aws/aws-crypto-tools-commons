package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Caching CMM behavior on one Language_Server (caching-cmm.md): two encrypts
 * through the same client reuse the cached data key, so their encrypted data
 * keys are byte-identical, until the cache's message limit forces a new one; and
 * clients that share one cache each get only the materials their own commitment
 * policy allows.
 *
 * <p>Target-only: the cache lives in one client on one server, so these run once
 * per target, gated on the {@code caching} Feature. The suite is committing and
 * non-signing, so the materials are cacheable under
 * {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}.
 */
class CachingCmmTests {

    private static final Set<String> FEATURES = Set.of("raw-aes", "caching");

    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    private static final byte[] PLAINTEXT =
        "esdk-test-server caching CMM plaintext".getBytes(StandardCharsets.UTF_8);

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    @ParameterizedTest(name = "cachedDataKeyIsReused {0}")
    @MethodSource("targets")
    void cachedDataKeyIsReused(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        String clientId = EsdkOps.createClient(target.endpoint(), EsdkClientConfigs.rawAesCaching(null));

        byte[] first = encryptedDataKeys(EsdkOps.encryptWithClient(target.endpoint(), clientId, PLAINTEXT, SUITE));
        byte[] second = encryptedDataKeys(EsdkOps.encryptWithClient(target.endpoint(), clientId, PLAINTEXT, SUITE));

        assertArrayEquals(first, second,
            target + ": a second encrypt within the cache limits must reuse the cached data key");
    }

    @ParameterizedTest(name = "messageLimitForcesNewDataKey {0}")
    @MethodSource("targets")
    void messageLimitForcesNewDataKey(LanguageServerTarget target) {
        FeatureGate.require(FEATURES, target);
        String clientId = EsdkOps.createClient(target.endpoint(), EsdkClientConfigs.rawAesCaching(1L));

        byte[] first = encryptedDataKeys(EsdkOps.encryptWithClient(target.endpoint(), clientId, PLAINTEXT, SUITE));
        byte[] second = encryptedDataKeys(EsdkOps.encryptWithClient(target.endpoint(), clientId, PLAINTEXT, SUITE));

        assertFalse(Arrays.equals(first, second),
            target + ": with limitMessages=1, a second encrypt must not reuse the cached data key");
    }

    /**
     * A client that requires commitment, encrypting after a client that forbids it
     * cached its materials in the same shared cache and partition, must not write a
     * non-committing message: its encrypt fails, or its message's algorithm suite is
     * committing.
     */
    @ParameterizedTest(name = "sharedCacheRespectsRequireCommitment {0}")
    @MethodSource("targets")
    void sharedCacheRespectsRequireCommitment(LanguageServerTarget target) {
        assertSharedCacheRespectsPolicy(target,
            ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    }

    /**
     * A client that forbids commitment, encrypting after a client that requires it
     * cached its materials in the same shared cache and partition, must not write a
     * committing message: its encrypt fails, or its message's algorithm suite is
     * non-committing.
     */
    @ParameterizedTest(name = "sharedCacheRespectsForbidCommitment {0}")
    @MethodSource("targets")
    void sharedCacheRespectsForbidCommitment(LanguageServerTarget target) {
        assertSharedCacheRespectsPolicy(target,
            ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
    }

    private static void assertSharedCacheRespectsPolicy(LanguageServerTarget target,
            ESDKCommitmentPolicy first, ESDKCommitmentPolicy second) {
        FeatureGate.require(FEATURES, target);
        String cacheName = "shared-" + UUID.randomUUID();
        requireSharedCache(target, cacheName);

        String firstClient = EsdkOps.createClient(target.endpoint(),
            EsdkClientConfigs.rawAesSharedCaching(first, cacheName, cacheName));
        String secondClient = EsdkOps.createClient(target.endpoint(),
            EsdkClientConfigs.rawAesSharedCaching(second, cacheName, cacheName));
        EsdkOps.encryptWithClient(target.endpoint(), firstClient, PLAINTEXT, null);

        byte[] ciphertext;
        try {
            ciphertext = EsdkOps.encryptWithClient(target.endpoint(), secondClient, PLAINTEXT, null);
        } catch (ESDKClientError expected) {
            return;
        }
        boolean committing = EsdkMessage.isCommitting(EsdkMessage.parse(ciphertext).algorithmSuiteId);
        assertTrue(committing == (second == ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT),
            target + ": a " + second + " client sharing a cache with a " + first
                + " client wrote a message its commitment policy does not allow");
    }

    /**
     * Skip, visibly, on a server that does not share a named cache: two same-policy
     * clients on one name and partition must reuse one cached data key.
     */
    private static void requireSharedCache(LanguageServerTarget target, String cacheName) {
        ESDKCommitmentPolicy policy = ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
        String probe = cacheName + "-probe";
        String a = EsdkOps.createClient(target.endpoint(), EsdkClientConfigs.rawAesSharedCaching(policy, cacheName, probe));
        String b = EsdkOps.createClient(target.endpoint(), EsdkClientConfigs.rawAesSharedCaching(policy, cacheName, probe));
        byte[] first = encryptedDataKeys(EsdkOps.encryptWithClient(target.endpoint(), a, PLAINTEXT, SUITE));
        byte[] second = encryptedDataKeys(EsdkOps.encryptWithClient(target.endpoint(), b, PLAINTEXT, SUITE));
        Assumptions.assumeTrue(Arrays.equals(first, second),
            target + " does not share a Caching CMM cache across clients by sharedCacheName");
    }

    /** The header's encrypted-data-key section (count and entries). */
    private static byte[] encryptedDataKeys(byte[] ciphertext) {
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        return Arrays.copyOfRange(message.bytes, message.edkCountOffset, message.contentTypeOffset);
    }
}
