package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RequiredEncryptionContextCmmConfig;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;

/**
 * Fully-offline ESDK client configurations for the blob round-trip Tests. Every
 * configuration here runs with NO AWS/KMS/network: only Raw-AES and Raw-RSA
 * keyrings, multi-keyrings combining those, and the Default and
 * Required-Encryption-Context CMMs — the keyring/CMM/algorithm-suite combinations
 * the Java ESDK supports offline (design "Java Hardening Pass (Offline)",
 * Requirements 2.1, 2.2, 2.5, 4.2, 4.3, 4.4).
 *
 * <p>The original single {@link #rawAes()} config (Raw-AES / Default CMM,
 * {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}) is preserved for the example Tests and
 * the stream round-trip; task 14.3 adds {@link #scenarios()} — a set of
 * round-trip-<em>compatible</em> {@link Scenario}s (same key material on encrypt
 * and decrypt) that broadens the generators feeding Property 1 while keeping the
 * property statement unchanged ({@code decrypt(encrypt(x)) == x}, byte-for-byte).
 *
 * <p>These builders use the generated <em>client</em> model shapes, keeping the
 * Tests dependent only on the one generated Test_Client.
 *
 * <p><strong>AWS KMS keyrings</strong> are excluded (they require AWS
 * credentials/OIDC; deferred to a future credentialed pass). The
 * <strong>Caching CMM</strong> is also excluded from these round-trip scenarios:
 * the AWS Encryption SDK for Java 3.x + Material Providers Library 1.x expose no
 * MPL caching CMM over MPL keyrings offline (the legacy
 * {@code CachingCryptoMaterialsManager} only wraps a legacy
 * {@code CryptoMaterialsManager}/{@code MasterKeyProvider}, not an MPL
 * {@code IKeyring}), so a caching CMM cannot be constructed for these keyrings
 * without a spec/library decision.
 */
public final class EsdkClientConfigs {

    /**
     * A fixed 32-byte wrapping key (all bytes distinct-enough for a valid AES-256
     * key; the exact value is irrelevant as long as encrypt and decrypt share it).
     */
    private static final byte[] WRAPPING_KEY_32 = new byte[] {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31
    };

    /** A second, distinct 32-byte wrapping key for multi-keyring coverage. */
    private static final byte[] WRAPPING_KEY_32_B = new byte[] {
        31, 30, 29, 28, 27, 26, 25, 24,
        23, 22, 21, 20, 19, 18, 17, 16,
        15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0
    };

    private static final String KEY_NAMESPACE = "esdk-test-server";
    private static final String KEY_NAME = "raw-aes-round-trip-key";
    private static final String KEY_NAME_B = "raw-aes-round-trip-key-b";
    private static final String RSA_KEY_NAME = "raw-rsa-round-trip-key";

    /**
     * A single RSA key pair, generated once and PEM-encoded, carrying BOTH the
     * public key (for encrypt) and the private key (for decrypt) so a Raw-RSA
     * keyring built from it round-trips on its own (raw-rsa-keyring.md).
     */
    private static final PemKeyPair RSA_KEY_PAIR = generateRsaPemKeyPair();

    private EsdkClientConfigs() {
    }

    /**
     * @return a fresh {@link ESDKClientConfig} for an offline Raw-AES / Default-CMM
     *     client with {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT} commitment. Preserved
     *     for the example Tests and the stream round-trip.
     */
    public static ESDKClientConfig rawAes() {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(defaultCmm(rawAesKeyring()))
            .build();
    }

    /**
     * @return a Raw-AES / Default-CMM config whose wrapping key is <em>different</em>
     *     from {@link #rawAes()}'s, so it cannot decrypt ciphertext produced by
     *     {@link #rawAes()} — used by the modeled-error transmission Tests to force
     *     an ESDK decrypt failure (an {@code ESDKClientError}).
     */
    public static ESDKClientConfig rawAesIncompatibleKey() {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(defaultCmm(rawAesKeyringB()))
            .build();
    }

    // -----------------------------------------------------------------------
    // Task 14.3: broadened, round-trip-compatible scenarios for Property 1.
    // -----------------------------------------------------------------------

    /**
     * A single round-trip scenario: one ESDK config (used to build BOTH the
     * encrypt and the decrypt client, so the material is guaranteed compatible),
     * an optional algorithm-suite override applied on encrypt, and the required
     * encryption-context keys the config's CMM demands (empty unless the CMM is a
     * Required-Encryption-Context CMM).
     *
     * @param label human-readable scenario name (diagnostics only).
     * @param config the offline ESDK client configuration.
     * @param algorithmSuiteId optional algorithm-suite override for encrypt, or
     *     {@code null} to use the client default.
     * @param requiredEncryptionContextKeys keys the CMM requires to be present in
     *     the encryption context on encrypt and supplied again on decrypt.
     */
    public record Scenario(
        String label,
        ESDKClientConfig config,
        ESDKAlgorithmSuiteId algorithmSuiteId,
        List<String> requiredEncryptionContextKeys) {

        @Override
        public String toString() {
            return label;
        }
    }

    /**
     * @return the representative set of offline, round-trip-compatible scenarios
     *     the broadened Property 1 iterates over: Raw-AES and Raw-RSA keyrings,
     *     multi-keyrings combining raw keyrings, the Default and
     *     Required-Encryption-Context CMMs, and committing / non-committing /
     *     no-KDF algorithm-suite selection. Every scenario keeps encrypt and
     *     decrypt material compatible so {@code decrypt(encrypt(x)) == x} holds.
     */
    public static List<Scenario> scenarios() {
        return List.of(
            // Raw-AES + Default CMM (the baseline), client-default suite.
            new Scenario("rawAes+default",
                require(defaultCmm(rawAesKeyring())), null, List.of()),

            // Raw-RSA + Default CMM, client-default suite (keyring has pub+priv).
            new Scenario("rawRsa+default",
                require(defaultCmm(rawRsaKeyring())), null, List.of()),

            // Multi-keyring combining two Raw-AES keyrings (generator + one child).
            new Scenario("multi(rawAes,rawAes)+default",
                require(defaultCmm(multiKeyring(rawAesKeyring(),
                    List.of(rawAesKeyringB())))), null, List.of()),

            // Multi-keyring combining a Raw-AES generator with a Raw-RSA child.
            new Scenario("multi(rawAes,rawRsa)+default",
                require(defaultCmm(multiKeyring(rawAesKeyring(),
                    List.of(rawRsaKeyring())))), null, List.of()),

            // Required-Encryption-Context CMM over a Default CMM / Raw-AES keyring.
            new Scenario("rawAes+requiredEncryptionContext",
                require(requiredEcCmm(defaultCmm(rawAesKeyring()),
                    List.of("purpose", "tenant"))),
                null, List.of("purpose", "tenant")),

            // Algorithm-suite selection: committing + signed suite (needs a
            // commit-key-capable commitment policy).
            new Scenario("rawAes+committingSigned",
                require(defaultCmm(rawAesKeyring())),
                ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
                List.of()),

            // Algorithm-suite selection: non-committing HKDF suite (commitment must
            // be forbidden on encrypt and allowed on decrypt).
            new Scenario("rawAes+nonCommittingHkdf",
                forbid(defaultCmm(rawAesKeyring())),
                ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256,
                List.of()),

            // Algorithm-suite selection: non-committing, no-KDF suite.
            new Scenario("rawAes+nonCommittingNoKdf",
                forbid(defaultCmm(rawAesKeyring())),
                ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF,
                List.of()));
    }

    // -----------------------------------------------------------------------
    // CMM builders.
    // -----------------------------------------------------------------------

    private static CryptographicMaterialsManager defaultCmm(Keyring keyring) {
        return CryptographicMaterialsManager.builder()
            .defaultMember(DefaultCmmConfig.builder().keyring(keyring).build())
            .build();
    }

    private static CryptographicMaterialsManager requiredEcCmm(
        CryptographicMaterialsManager underlying, List<String> requiredKeys) {
        return CryptographicMaterialsManager.builder()
            .requiredEncryptionContext(RequiredEncryptionContextCmmConfig.builder()
                .underlyingCMM(underlying)
                .requiredEncryptionContextKeys(requiredKeys)
                .build())
            .build();
    }

    /** Wrap a CMM in a client config that requires commitment on encrypt+decrypt. */
    private static ESDKClientConfig require(CryptographicMaterialsManager cmm) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(cmm)
            .build();
    }

    /** Wrap a CMM in a client config that forbids commitment (non-committing suites). */
    private static ESDKClientConfig forbid(CryptographicMaterialsManager cmm) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .cmm(cmm)
            .build();
    }

    // -----------------------------------------------------------------------
    // Keyring builders.
    // -----------------------------------------------------------------------

    private static Keyring rawAesKeyring() {
        return Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(KEY_NAME)
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY_32.clone()))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
    }

    private static Keyring rawAesKeyringB() {
        return Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(KEY_NAME_B)
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY_32_B.clone()))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
    }

    private static Keyring rawRsaKeyring() {
        return Keyring.builder()
            .rawRsa(RawRsaKeyringConfig.builder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(RSA_KEY_NAME)
                .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
                .publicKey(ByteBuffer.wrap(RSA_KEY_PAIR.publicPem()))
                .privateKey(ByteBuffer.wrap(RSA_KEY_PAIR.privatePem()))
                .build())
            .build();
    }

    private static Keyring multiKeyring(Keyring generator, List<Keyring> children) {
        return Keyring.builder()
            .multi(MultiKeyringConfig.builder()
                .generator(generator)
                .childKeyrings(children)
                .build())
            .build();
    }

    // -----------------------------------------------------------------------
    // RSA key-pair generation (offline; done once).
    // -----------------------------------------------------------------------

    private record PemKeyPair(byte[] publicPem, byte[] privatePem) {
    }

    private static PemKeyPair generateRsaPemKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            byte[] publicPem = pem("PUBLIC KEY", keyPair.getPublic().getEncoded());
            byte[] privatePem = pem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
            return new PemKeyPair(publicPem, privatePem);
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate an offline RSA key pair", e);
        }
    }

    /** Wrap DER bytes in a PEM block ({@code -----BEGIN <type>-----} ... 64-col base64). */
    private static byte[] pem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
            .encodeToString(der);
        String block = "-----BEGIN " + type + "-----\n"
            + base64 + "\n"
            + "-----END " + type + "-----\n";
        return block.getBytes(StandardCharsets.UTF_8);
    }
}
