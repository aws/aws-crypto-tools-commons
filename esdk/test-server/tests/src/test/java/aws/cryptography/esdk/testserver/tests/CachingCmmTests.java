package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Caching CMM behavior on one Language_Server (caching-cmm.md): two encrypts
 * through the same client reuse the cached data key, so their encrypted data
 * keys are byte-identical, until the cache's message limit forces a new one.
 *
 * <p>Target-only: the cache lives in one client on one server, so these run once
 * per target, gated on the {@code caching} Feature. The suite is committing and
 * non-signing, so the materials are cacheable under
 * {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}.
 */
class CachingCmmTests {

    private static final Set<String> FEATURES = Set.of("MPL", "caching");

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

    /** The header's encrypted-data-key section (count and entries). */
    private static byte[] encryptedDataKeys(byte[] ciphertext) {
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        return Arrays.copyOfRange(message.bytes, message.edkCountOffset, message.contentTypeOffset);
    }
}
