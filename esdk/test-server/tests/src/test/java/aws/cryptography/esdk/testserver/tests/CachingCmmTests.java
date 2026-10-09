package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import aws.cryptography.esdk.testserver.client.model.GetCallCountsInput;
import aws.cryptography.esdk.testserver.client.model.GetCallCountsOutput;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.TestHooks;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Caching CMM behavior ({@code spec/framework/caching-cmm.md}). A per-server property: one
 * client encrypts and decrypts many messages through one cache, so every test runs once per
 * target, against a single client whose cache persists across its calls.
 *
 * <p>Two observations make the cache's behavior visible from outside the server:
 *
 * <ul>
 *   <li>Which data key encrypted a message. The cache stores the encrypted data keys with the
 *       materials, so messages that reuse a cached data key carry byte-identical encrypted data
 *       keys in their headers, and a new data key carries different ones.</li>
 *   <li>{@code GetCallCounts}: how many times the caching CMM called the CMM it wraps.</li>
 * </ul>
 *
 * <p>The concurrency tests fire calls at one client at the same time. Every implementation must
 * keep each data key within its limits under concurrency. Sharing one request among concurrent
 * misses is checked separately and gated by the {@code caching-cmm-concurrent-misses-not-shared}
 * known bug.
 */
class CachingCmmTests {

    private static final Set<String> FEATURES = Set.of("caching", "raw-aes");
    private static final String NOT_SHARED_BUG = "caching-cmm-concurrent-misses-not-shared";
    private static final ESDKAlgorithmSuiteId SUITE =
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final byte[] WRAPPING_KEY = new byte[] {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x0f,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x00,
    };
    private static final int CONCURRENCY = 10;
    /** Long enough that every concurrent call reaches the caching CMM before the first request returns. */
    private static final int UNDERLYING_DELAY_MS = 200;

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /**
     * Usage limits for one caching CMM; null means the implementation's default.
     * {@code delayMs} is the test-only delay before each call to the underlying CMM.
     */
    private record Limits(Long messages, Long bytes, int ttlSeconds, int delayMs) {
        static Limits messages(long messages) {
            return new Limits(messages, null, 60, 0);
        }

        static Limits bytes(long bytes) {
            return new Limits(null, bytes, 60, 0);
        }

        /** The same limits, with concurrent calls made to overlap. */
        Limits overlapping() {
            return new Limits(messages, bytes, ttlSeconds, UNDERLYING_DELAY_MS);
        }
    }

    /** One client with a caching CMM over a Raw-AES keyring, and the calls tests make with it. */
    private record CachingClient(ESDKTestServerClient client, String clientId) {

        static CachingClient create(LanguageServerTarget target, Limits limits,
                                    ESDKCommitmentPolicy policy) {
            FeatureGate.require(FEATURES, target);
            CachingCmmConfig.Builder caching = CachingCmmConfig.builder()
                .underlyingCMM(CryptographicMaterialsManager.builder()
                    .defaultMember(DefaultCmmConfig.builder().keyring(rawAes()).build())
                    .build())
                .cacheLimitTtlSeconds(limits.ttlSeconds());
            if (limits.messages() != null) {
                caching.limitMessages(limits.messages());
            }
            if (limits.bytes() != null) {
                caching.limitBytes(limits.bytes());
            }
            ESDKClientConfig config = ESDKClientConfig.builder()
                .commitmentPolicy(policy)
                .cmm(CryptographicMaterialsManager.builder().caching(caching.build()).build())
                .build();
            CreateClientInput.Builder input = CreateClientInput.builder().config(config);
            if (limits.delayMs() > 0) {
                input.testHooks(TestHooks.builder()
                    .cachingCmmUnderlyingDelayMilliseconds(limits.delayMs())
                    .build());
            }
            CreateClientInput request = input.build();
            ESDKTestServerClient client = TestServerClients.forEndpoint(target.endpoint());
            String clientId = TestServerClients.withRetry(() -> client.createClient(request)).getClientId();
            return new CachingClient(client, clientId);
        }

        static CachingClient create(LanguageServerTarget target, Limits limits) {
            return create(target, limits, ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
        }

        byte[] encrypt(byte[] plaintext) {
            return encrypt(plaintext, Map.of(), SUITE);
        }

        byte[] encrypt(byte[] plaintext, Map<String, String> context, ESDKAlgorithmSuiteId suite) {
            EncryptInput.Builder input = EncryptInput.builder()
                .clientId(clientId)
                .plaintext(ByteBuffer.wrap(plaintext))
                .algorithmSuiteId(suite);
            if (!context.isEmpty()) {
                input.encryptionContext(context);
            }
            EncryptInput request = input.build();
            return EsdkOps.toArray(TestServerClients.withRetry(() -> client.encrypt(request)).getCiphertext());
        }

        byte[] decrypt(byte[] ciphertext) {
            DecryptInput request = DecryptInput.builder()
                .clientId(clientId)
                .ciphertext(ByteBuffer.wrap(ciphertext))
                .build();
            return EsdkOps.toArray(TestServerClients.withRetry(() -> client.decrypt(request)).getPlaintext());
        }

        GetCallCountsOutput callCounts() {
            GetCallCountsInput request = GetCallCountsInput.builder().clientId(clientId).build();
            return TestServerClients.withRetry(() -> client.getCallCounts(request));
        }
    }

    private static Keyring rawAes() {
        return Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace("esdk-test-server")
                .keyName("caching-cmm-key")
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
    }

    /** The header's encrypted data key section: identical for messages that share a data key. */
    private static String dataKeyOf(byte[] ciphertext) {
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        return HexFormat.of().formatHex(
            ciphertext, message.edkCountOffset, message.contentTypeOffset);
    }

    /** Messages per data key, in the order each data key first appears. */
    private static List<Integer> messagesPerDataKey(List<byte[]> ciphertexts) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (byte[] ciphertext : ciphertexts) {
            counts.merge(dataKeyOf(ciphertext), 1, Integer::sum);
        }
        return new ArrayList<>(counts.values());
    }

    private static byte[] plaintext(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) i;
        }
        return bytes;
    }

    private static List<byte[]> encryptInSequence(CachingClient client, int count, int length) {
        List<byte[]> ciphertexts = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            ciphertexts.add(client.encrypt(plaintext(length)));
        }
        return ciphertexts;
    }

    /** Runs {@code count} calls at once, released together, and returns their results in order. */
    private static <T> List<T> concurrently(int count, Callable<T> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(count);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return call.call();
                }));
            }
            start.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get(60, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    // ---------------------------------------------------------------------------
    // One call at a time
    // ---------------------------------------------------------------------------

    /** A data key encrypts up to limitMessages messages; the next message gets a new one. */
    @ParameterizedTest(name = "reusesDataKeyUpToLimitMessages {0}")
    @MethodSource("targets")
    void reusesDataKeyUpToLimitMessages(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(3));

        List<byte[]> ciphertexts = encryptInSequence(client, 7, 16);

        assertEquals(List.of(3, 3, 1), messagesPerDataKey(ciphertexts),
            target + ": with limitMessages 3, seven messages must use three data keys");
        assertEquals(3, client.callCounts().getCachingCmmGetEncryptionMaterialsCalls(),
            target + ": each new data key is one call to the underlying CMM");
    }

    /** A data key encrypts up to limitBytes bytes; the message that would exceed it gets a new one. */
    @ParameterizedTest(name = "reusesDataKeyUpToLimitBytes {0}")
    @MethodSource("targets")
    void reusesDataKeyUpToLimitBytes(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.bytes(10));

        List<byte[]> ciphertexts = encryptInSequence(client, 5, 4);

        assertEquals(List.of(2, 2, 1), messagesPerDataKey(ciphertexts),
            target + ": with limitBytes 10, two 4-byte messages fit per data key");
    }

    /** A message larger than limitBytes gets its own data key, which is not cached. */
    @ParameterizedTest(name = "messageOverLimitBytesIsNotCached {0}")
    @MethodSource("targets")
    void messageOverLimitBytesIsNotCached(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.bytes(10));

        List<byte[]> ciphertexts = encryptInSequence(client, 3, 11);

        assertEquals(List.of(1, 1, 1), messagesPerDataKey(ciphertexts),
            target + ": an 11-byte message exceeds limitBytes 10, so its data key must not be reused");
    }

    /** Messages with different encryption contexts use different cache entries, so different data keys. */
    @ParameterizedTest(name = "encryptionContextSelectsCacheEntry {0}")
    @MethodSource("targets")
    void encryptionContextSelectsCacheEntry(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(10));
        Map<String, String> a = Map.of("tenant", "a");
        Map<String, String> b = Map.of("tenant", "b");

        List<byte[]> ciphertexts = List.of(
            client.encrypt(plaintext(16), a, SUITE),
            client.encrypt(plaintext(16), b, SUITE),
            client.encrypt(plaintext(16), a, SUITE),
            client.encrypt(plaintext(16), b, SUITE));

        assertEquals(List.of(2, 2), messagesPerDataKey(ciphertexts),
            target + ": each encryption context must reuse its own data key");
    }

    /** A cached data key is not used after cacheLimitTtlSeconds. */
    @ParameterizedTest(name = "dataKeyExpiresAfterTtl {0}")
    @MethodSource("targets")
    void dataKeyExpiresAfterTtl(LanguageServerTarget target) throws InterruptedException {
        CachingClient client = CachingClient.create(target, new Limits(null, null, 1, 0));

        byte[] first = client.encrypt(plaintext(16));
        Thread.sleep(1500);
        byte[] second = client.encrypt(plaintext(16));

        assertEquals(List.of(1, 1), messagesPerDataKey(List.of(first, second)),
            target + ": a data key cached with a 1-second TTL must not be used 1.5 seconds later");
    }

    /** Materials for a suite with an identity KDF are never cached (caching-cmm.md#get-encryption-materials). */
    @ParameterizedTest(name = "identityKdfSuiteIsNotCached {0}")
    @MethodSource("targets")
    void identityKdfSuiteIsNotCached(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(10),
            ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
        ESDKAlgorithmSuiteId noKdf = ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;

        List<byte[]> ciphertexts = List.of(
            client.encrypt(plaintext(16), Map.of(), noKdf),
            client.encrypt(plaintext(16), Map.of(), noKdf),
            client.encrypt(plaintext(16), Map.of(), noKdf));

        assertEquals(List.of(1, 1, 1), messagesPerDataKey(ciphertexts),
            target + ": a suite with an identity KDF must get a new data key for every message");
    }

    /** Decrypting the same message again uses the cached decryption materials. */
    @ParameterizedTest(name = "decryptMaterialsAreCached {0}")
    @MethodSource("targets")
    void decryptMaterialsAreCached(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(10));
        byte[] plaintext = plaintext(16);
        byte[] ciphertext = client.encrypt(plaintext);

        for (int i = 0; i < 3; i++) {
            assertArrayEquals(plaintext, client.decrypt(ciphertext), target + ": round trip");
        }

        assertEquals(1, client.callCounts().getCachingCmmDecryptMaterialsCalls(),
            target + ": three decrypts of one message must make one call to the underlying CMM");
    }

    /** Messages with different data keys need separate decryption materials. */
    @ParameterizedTest(name = "decryptCacheIsPerDataKey {0}")
    @MethodSource("targets")
    void decryptCacheIsPerDataKey(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(1));
        byte[] first = client.encrypt(plaintext(16));
        byte[] second = client.encrypt(plaintext(16));

        client.decrypt(first);
        client.decrypt(second);
        client.decrypt(first);

        assertEquals(2, client.callCounts().getCachingCmmDecryptMaterialsCalls(),
            target + ": two messages with different data keys need two calls to the underlying CMM");
    }

    // ---------------------------------------------------------------------------
    // Concurrent calls
    // ---------------------------------------------------------------------------

    /** Concurrent encrypts never use a data key for more than limitMessages messages. */
    @ParameterizedTest(name = "concurrentEncryptsStayWithinLimitMessages {0}")
    @MethodSource("targets")
    void concurrentEncryptsStayWithinLimitMessages(LanguageServerTarget target) throws Exception {
        CachingClient client = CachingClient.create(target, Limits.messages(5).overlapping());

        List<byte[]> ciphertexts = concurrently(50, () -> client.encrypt(plaintext(16)));

        for (int messages : messagesPerDataKey(ciphertexts)) {
            assertTrue(messages <= 5,
                target + ": a data key encrypted " + messages + " messages, over limitMessages 5");
        }
    }

    /** Concurrent encrypts of different sizes never use a data key for more than limitBytes bytes. */
    @ParameterizedTest(name = "concurrentEncryptsStayWithinLimitBytes {0}")
    @MethodSource("targets")
    void concurrentEncryptsStayWithinLimitBytes(LanguageServerTarget target) throws Exception {
        CachingClient client = CachingClient.create(target, Limits.bytes(10).overlapping());
        int[] lengths = {6, 3, 1, 4, 4, 2, 9, 1, 1, 5, 3, 7};
        AtomicInteger next = new AtomicInteger();

        List<Map.Entry<String, Integer>> results = concurrently(lengths.length, () -> {
            int length = lengths[next.getAndIncrement()];
            return Map.entry(dataKeyOf(client.encrypt(plaintext(length))), length);
        });

        Map<String, Integer> bytesPerDataKey = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> result : results) {
            bytesPerDataKey.merge(result.getKey(), result.getValue(), Integer::sum);
        }
        for (int bytes : bytesPerDataKey.values()) {
            assertTrue(bytes <= 10,
                target + ": a data key encrypted " + bytes + " bytes, over limitBytes 10");
        }
    }

    /**
     * Concurrent encrypts that miss the cache share one request for a data key,
     * up to limitMessages callers per data key.
     */
    @ParameterizedTest(name = "concurrentEncryptsShareDataKeys {0}")
    @MethodSource("targets")
    void concurrentEncryptsShareDataKeys(LanguageServerTarget target) throws Exception {
        CachingClient client = CachingClient.create(target, Limits.messages(5).overlapping());

        List<byte[]> ciphertexts = concurrently(CONCURRENCY, () -> client.encrypt(plaintext(16)));

        KnownBugGate.gateDeclared(NOT_SHARED_BUG, target, () -> {
            assertEquals(List.of(5, 5), messagesPerDataKey(ciphertexts),
                target + ": ten concurrent encrypts with limitMessages 5 must share two data keys");
            assertEquals(2, client.callCounts().getCachingCmmGetEncryptionMaterialsCalls(),
                target + ": two data keys must take two calls to the underlying CMM");
        });
    }

    /** After a warm entry runs out of uses, the remaining concurrent callers share one new data key. */
    @ParameterizedTest(name = "concurrentEncryptsAfterWarmEntryShareDataKeys {0}")
    @MethodSource("targets")
    void concurrentEncryptsAfterWarmEntryShareDataKeys(LanguageServerTarget target) throws Exception {
        CachingClient client = CachingClient.create(target, Limits.messages(5).overlapping());
        byte[] warm = client.encrypt(plaintext(16));

        List<byte[]> ciphertexts = new ArrayList<>(List.of(warm));
        ciphertexts.addAll(concurrently(CONCURRENCY, () -> client.encrypt(plaintext(16))));

        KnownBugGate.gateDeclared(NOT_SHARED_BUG, target, () -> {
            List<Integer> perDataKey = messagesPerDataKey(ciphertexts);
            assertEquals(3, perDataKey.size(),
                target + ": eleven encrypts with limitMessages 5 need three data keys, got " + perDataKey);
            assertEquals(5, perDataKey.get(0),
                target + ": the warm data key must be used until limitMessages, got " + perDataKey);
        });
    }

    /** Concurrent decrypts of one message share one request for decryption materials. */
    @ParameterizedTest(name = "concurrentDecryptsShareOneRequest {0}")
    @MethodSource("targets")
    void concurrentDecryptsShareOneRequest(LanguageServerTarget target) throws Exception {
        CachingClient client = CachingClient.create(target, Limits.messages(5).overlapping());
        byte[] plaintext = plaintext(16);
        byte[] ciphertext = client.encrypt(plaintext);

        List<byte[]> recovered = concurrently(CONCURRENCY, () -> client.decrypt(ciphertext));

        for (byte[] result : recovered) {
            assertArrayEquals(plaintext, result, target + ": round trip");
        }
        KnownBugGate.gateDeclared(NOT_SHARED_BUG, target, () ->
            assertEquals(1, client.callCounts().getCachingCmmDecryptMaterialsCalls(),
                target + ": ten concurrent decrypts of one message must make one call to the underlying CMM"));
    }
}
