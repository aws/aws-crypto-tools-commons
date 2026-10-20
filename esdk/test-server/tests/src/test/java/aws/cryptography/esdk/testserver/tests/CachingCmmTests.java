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
import aws.cryptography.esdk.testserver.client.model.AdvanceClockInput;
import aws.cryptography.esdk.testserver.client.model.DecryptConcurrentlyInput;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.EncryptConcurrentlyInput;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import aws.cryptography.esdk.testserver.client.model.GenericServerError;
import aws.cryptography.esdk.testserver.client.model.GetCallCountsInput;
import aws.cryptography.esdk.testserver.client.model.GetCallCountsOutput;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
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
 * <p>Tests expire entries with {@code AdvanceClock}, which moves the clock of the client's caches,
 * instead of waiting.
 *
 * <p>The concurrency tests ask the server to run many calls on one client at once
 * ({@code EncryptConcurrently}, {@code DecryptConcurrently}), so the fan-out happens in the
 * language under test. Every implementation must
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

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    /** Usage limits for one caching CMM; null means the implementation's default. */
    private record Limits(Long messages, Long bytes, int ttlSeconds) {
        static Limits messages(long messages) {
            return new Limits(messages, null, 60);
        }

        static Limits bytes(long bytes) {
            return new Limits(null, bytes, 60);
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
            CreateClientInput request = CreateClientInput.builder().config(config).build();
            ESDKTestServerClient client = TestServerClients.forEndpoint(target.endpoint());
            String clientId = TestServerClients.withRetry(() -> client.createClient(request)).getClientId();
            CachingClient created = new CachingClient(client, clientId);
            // A server that supports caching but not yet the test-only operations skips, visibly.
            try {
                created.callCounts();
            } catch (GenericServerError e) {
                Assumptions.abort(target + " does not implement the test-only operations: "
                    + e.getMessage());
            }
            return created;
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

        /** Encrypt every plaintext at the same time, inside the server. */
        List<byte[]> encryptConcurrently(List<byte[]> plaintexts) {
            EncryptConcurrentlyInput request = EncryptConcurrentlyInput.builder()
                .clientId(clientId)
                .plaintexts(plaintexts.stream().map(ByteBuffer::wrap).toList())
                .algorithmSuiteId(SUITE)
                .build();
            return TestServerClients.withRetry(() -> client.encryptConcurrently(request))
                .getCiphertexts().stream().map(EsdkOps::toArray).toList();
        }

        /** Decrypt every ciphertext at the same time, inside the server. */
        List<byte[]> decryptConcurrently(List<byte[]> ciphertexts) {
            DecryptConcurrentlyInput request = DecryptConcurrentlyInput.builder()
                .clientId(clientId)
                .ciphertexts(ciphertexts.stream().map(ByteBuffer::wrap).toList())
                .build();
            return TestServerClients.withRetry(() -> client.decryptConcurrently(request))
                .getPlaintexts().stream().map(EsdkOps::toArray).toList();
        }

        /** Move the clock of this client's caches forward. */
        void advanceClock(long milliseconds) {
            AdvanceClockInput request = AdvanceClockInput.builder()
                .clientId(clientId)
                .milliseconds(milliseconds)
                .build();
            TestServerClients.withRetry(() -> client.advanceClock(request));
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

    private static List<byte[]> plaintexts(int count, int length) {
        List<byte[]> plaintexts = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            plaintexts.add(plaintext(length));
        }
        return plaintexts;
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

    /** A cached data key is used until cacheLimitTtlSeconds, and not after. */
    @ParameterizedTest(name = "dataKeyExpiresAfterTtl {0}")
    @MethodSource("targets")
    void dataKeyExpiresAfterTtl(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, new Limits(null, null, 60));

        byte[] first = client.encrypt(plaintext(16));
        client.advanceClock(59_000);
        byte[] second = client.encrypt(plaintext(16));
        client.advanceClock(2_000);
        byte[] third = client.encrypt(plaintext(16));

        assertEquals(List.of(2, 1), messagesPerDataKey(List.of(first, second, third)),
            target + ": a data key cached with a 60-second TTL is reused at 59 seconds and not at 61");
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
    void concurrentEncryptsStayWithinLimitMessages(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(5));

        List<byte[]> ciphertexts = client.encryptConcurrently(plaintexts(50, 16));

        for (int messages : messagesPerDataKey(ciphertexts)) {
            assertTrue(messages <= 5,
                target + ": a data key encrypted " + messages + " messages, over limitMessages 5");
        }
    }

    /** Concurrent encrypts of different sizes never use a data key for more than limitBytes bytes. */
    @ParameterizedTest(name = "concurrentEncryptsStayWithinLimitBytes {0}")
    @MethodSource("targets")
    void concurrentEncryptsStayWithinLimitBytes(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.bytes(10));
        int[] lengths = {6, 3, 1, 4, 4, 2, 9, 1, 1, 5, 3, 7};
        List<byte[]> plaintexts = new ArrayList<>();
        for (int length : lengths) {
            plaintexts.add(plaintext(length));
        }

        List<byte[]> ciphertexts = client.encryptConcurrently(plaintexts);

        Map<String, Integer> bytesPerDataKey = new LinkedHashMap<>();
        for (int i = 0; i < lengths.length; i++) {
            bytesPerDataKey.merge(dataKeyOf(ciphertexts.get(i)), lengths[i], Integer::sum);
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
    void concurrentEncryptsShareDataKeys(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(5));

        List<byte[]> ciphertexts = client.encryptConcurrently(plaintexts(CONCURRENCY, 16));

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
    void concurrentEncryptsAfterWarmEntryShareDataKeys(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(5));
        byte[] warm = client.encrypt(plaintext(16));

        List<byte[]> ciphertexts = new ArrayList<>(List.of(warm));
        ciphertexts.addAll(client.encryptConcurrently(plaintexts(CONCURRENCY, 16)));

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
    void concurrentDecryptsShareOneRequest(LanguageServerTarget target) {
        CachingClient client = CachingClient.create(target, Limits.messages(5));
        byte[] plaintext = plaintext(16);
        byte[] ciphertext = client.encrypt(plaintext);

        List<byte[]> recovered = client.decryptConcurrently(
            Collections.nCopies(CONCURRENCY, ciphertext));

        for (byte[] result : recovered) {
            assertArrayEquals(plaintext, result, target + ": round trip");
        }
        KnownBugGate.gateDeclared(NOT_SHARED_BUG, target, () ->
            assertEquals(1, client.callCounts().getCachingCmmDecryptMaterialsCalls(),
                target + ": ten concurrent decrypts of one message must make one call to the underlying CMM"));
    }
}
