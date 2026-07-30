package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.AwsKmsDiscoveryKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsMrkMultiKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsMultiKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.esdk.testserver.client.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RequiredEncryptionContextCmmConfig;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
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
 * <p><strong>AWS KMS keyrings</strong> are contributed to {@link #scenarios()} as
 * online, <strong>required</strong> scenarios (task 15.5): they are always
 * contributed and always run against the {@code KMS_Test_Resources}, whose ARNs
 * default in {@link KmsRuntimeConfig} so no environment variables are needed to
 * target the shared keys. A run does not pass unless these scenarios run and
 * pass, so AWS credentials (developer credentials locally, GitHub OIDC in CI)
 * must be present — there is no offline skip. Only {@link #offlineScenarios()} is
 * credential-free; it feeds the arbitrary-plaintext property tests, which stay
 * offline. The <strong>Caching CMM</strong> remains excluded from these round-trip
 * scenarios entirely:
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

    /**
     * @return a Raw-AES / Default-CMM config carrying the given commitment
     *     {@code policy}. Used by {@code KeyCommitmentTests} to exercise all three
     *     commitment policies against the full algorithm-suite set; the suite is
     *     selected per-{@code Encrypt} via {@code EncryptInput.algorithmSuiteId}.
     *     Fully offline (Raw-AES); the same keyring works for every suite,
     *     including signing suites.
     */
    public static ESDKClientConfig rawAesWithCommitmentPolicy(ESDKCommitmentPolicy policy) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(policy)
            .cmm(defaultCmm(rawAesKeyring()))
            .build();
    }

    /**
     * @return a Raw-AES multi-keyring (generator + one child, so two EDKs) Default-CMM config
     *     under {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}, with no encrypted-data-key cap. The
     *     two raw-AES keyrings both round-trip, and either alone can decrypt.
     */
    public static ESDKClientConfig rawAesMulti() {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(defaultCmm(multiKeyring(rawAesKeyring(), List.of(rawAesKeyringB()))))
            .build();
    }

    /**
     * @return the same two-EDK multi-keyring config as {@link #rawAesMulti()} but with the
     *     encrypted-data-key count capped at {@code maxEncryptedDataKeys}.
     */
    public static ESDKClientConfig rawAesMultiWithMaxEdks(long maxEncryptedDataKeys) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .maxEncryptedDataKeys(maxEncryptedDataKeys)
            .cmm(defaultCmm(multiKeyring(rawAesKeyring(), List.of(rawAesKeyringB()))))
            .build();
    }

    /**
     * @return a Raw-AES config whose CMM is a Required-Encryption-Context CMM over a Default CMM,
     *     requiring {@code requiredKeys} (dropped from the header on encrypt, demanded again on
     *     decrypt). Fully offline.
     */
    public static ESDKClientConfig rawAesRequiredEc(List<String> requiredKeys) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(requiredEcCmm(defaultCmm(rawAesKeyring()), requiredKeys))
            .build();
    }

    /**
     * @return a Default-CMM config over ONLY the second Raw-AES keyring (key "b"). Used to prove a
     *     decrypt keyring holding just one of several EDKs' wrapping keys can still decrypt.
     */
    public static ESDKClientConfig rawAesBOnly() {
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(defaultCmm(rawAesKeyringB()))
            .build();
    }

    /**
     * @return a Default-CMM config over a Raw-RSA keyring built with the PUBLIC key only (no private
     *     key), so it can wrap on encrypt but cannot unwrap on decrypt. Non-committing so a
     *     public-only asymmetric keyring is valid.
     */
    public static ESDKClientConfig rawRsaPublicOnly() {
        Keyring publicOnly = Keyring.builder()
            .rawRsa(RawRsaKeyringConfig.builder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(RSA_KEY_NAME)
                .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
                .publicKey(ByteBuffer.wrap(RSA_KEY_PAIR.publicPem()))
                .build())
            .build();
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .cmm(defaultCmm(publicOnly))
            .build();
    }

    // -----------------------------------------------------------------------
    // Task 14.3: broadened, round-trip-compatible scenarios for Property 1.
    // -----------------------------------------------------------------------

    /**
     * A single round-trip scenario. {@code config} builds the <em>encrypt</em>
     * client; {@code decryptConfig} builds the <em>decrypt</em> client. For most
     * scenarios {@code decryptConfig} is {@code null} and {@code config} is used
     * for BOTH legs, so the material is guaranteed compatible. A distinct
     * {@code decryptConfig} is only needed when the encrypt and decrypt legs must
     * use different keyrings for the same round trip — notably the
     * {@code AwsKmsDiscovery} scenario, where encrypt uses an encrypting KMS
     * keyring and decrypt uses a decrypt-only discovery keyring over the same
     * account/region (design "KMS Keyring Coverage (Online)").
     *
     * @param label human-readable scenario name (diagnostics only).
     * @param config the ESDK client configuration for the encrypt leg (and, when
     *     {@code decryptConfig} is {@code null}, the decrypt leg too).
     * @param algorithmSuiteId optional algorithm-suite override for encrypt, or
     *     {@code null} to use the client default.
     * @param requiredEncryptionContextKeys keys the CMM requires to be present in
     *     the encryption context on encrypt and supplied again on decrypt.
     * @param decryptConfig optional distinct config for the decrypt leg, or
     *     {@code null} to reuse {@code config} on both legs.
     */
    public record Scenario(
        String label,
        ESDKClientConfig config,
        ESDKAlgorithmSuiteId algorithmSuiteId,
        List<String> requiredEncryptionContextKeys,
        ESDKClientConfig decryptConfig) {

        /**
         * Convenience constructor for the common case where one config builds both
         * the encrypt and decrypt client (no distinct decrypt config).
         */
        public Scenario(
            String label,
            ESDKClientConfig config,
            ESDKAlgorithmSuiteId algorithmSuiteId,
            List<String> requiredEncryptionContextKeys) {
            this(label, config, algorithmSuiteId, requiredEncryptionContextKeys, null);
        }

        /**
         * @return the config to build the decrypt client with: the distinct
         *     {@link #decryptConfig()} when present, otherwise {@link #config()}.
         */
        public ESDKClientConfig decryptConfigOrDefault() {
            return decryptConfig != null ? decryptConfig : config;
        }

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
        List<Scenario> scenarios = new ArrayList<>(offlineScenarios());
        // Online KMS scenarios (Requirements 14.1, 14.2). These are REQUIRED: they
        // are always contributed and always run against the KMS_Test_Resources —
        // whose ARNs default in KmsRuntimeConfig, so no environment variables are
        // needed to target the shared keys — and a run does not pass unless they
        // run and pass. AWS credentials (developer creds locally, OIDC in CI) must
        // therefore be present; there is no offline skip.
        KmsRuntimeConfig kms = KmsRuntimeConfig.fromRuntime();
        // Ensure this JVM's ambient AWS region matches the configured KMS region
        // (design: KMS runtime configuration).
        kms.configureAwsRegion();
        scenarios.addAll(kmsScenarios(kms));
        return List.copyOf(scenarios);
    }

    /**
     * @return the fully-offline, round-trip-compatible scenarios (no AWS access):
     *     Raw-AES and Raw-RSA keyrings, multi-keyrings combining raw keyrings, the
     *     Default and Required-Encryption-Context CMMs, and committing /
     *     non-committing / no-KDF algorithm-suite selection. Always contributed.
     */
    public static List<Scenario> offlineScenarios() {
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
    // Task 15.5: online, credential-gated KMS scenarios.
    // -----------------------------------------------------------------------

    /**
     * Build the online KMS round-trip scenarios from a complete {@link
     * KmsRuntimeConfig} (Requirements 14.1, 14.2). Each is round-trip-compatible:
     * the same key material decrypts what it encrypted, EXCEPT the discovery
     * scenario, which encrypts with the symmetric KMS keyring and decrypts with a
     * KMS discovery keyring over the same account/region (via the Scenario's
     * distinct {@code decryptConfig}). All use the client-default committing suite
     * under {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}; the RSA keyring supplies its
     * KMS key id + RSAES-OAEP-SHA-256 padding (the server fetches the public key
     * from KMS at construction when the config omits it).
     *
     * @param kms the resolved, complete KMS runtime configuration.
     * @return the KMS scenarios contributed to {@link #scenarios()} when gated on.
     */
    private static List<Scenario> kmsScenarios(KmsRuntimeConfig kms) {
        return List.of(
            // AwsKms: single symmetric KMS key on both legs.
            new Scenario("awsKms",
                require(defaultCmm(awsKmsKeyring(kms.symmetricKeyArn()))), null, List.of()),

            // AwsKmsMrk: single multi-region KMS key on both legs.
            new Scenario("awsKmsMrk",
                require(defaultCmm(awsKmsMrkKeyring(kms.mrkArn()))), null, List.of()),

            // AwsKmsMultiKeyring: symmetric key as generator (+ MRK as a child key).
            new Scenario("awsKmsMultiKeyring",
                require(defaultCmm(awsKmsMultiKeyring(
                    kms.symmetricKeyArn(), List.of(kms.mrkArn())))), null, List.of()),

            // AwsKmsMrkMultiKeyring: the first MRK as generator + the SECOND MRK
            // as a child, so the MRK-aware multi-keyring spans two genuinely
            // distinct multi-region keys (both KMS_Test_Resources MRKs).
            new Scenario("awsKmsMrkMultiKeyring",
                require(defaultCmm(awsKmsMrkMultiKeyring(
                    kms.mrkArn(), List.of(kms.mrk2Arn())))), null, List.of()),

            // AwsKmsRsa: asymmetric RSA KMS key with RSAES-OAEP-SHA-256 padding.
            // The AwsKmsRsaKeyring rejects algorithm suites with asymmetric
            // (ECDSA) signing, so pin a committing, NON-signing suite rather than
            // the client-default committing+ECDSA suite (still commitment-capable,
            // so REQUIRE_ENCRYPT_REQUIRE_DECRYPT is satisfied).
            new Scenario("awsKmsRsa",
                require(defaultCmm(awsKmsRsaKeyring(
                    kms.rsaKeyArn(), KmsRsaEncryptionAlgorithm.RSAES_OAEP_SHA_256))),
                ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                List.of()),

            // AwsKmsDiscovery: encrypt with the symmetric KMS keyring, decrypt with
            // a KMS discovery keyring over the same region (distinct decryptConfig).
            new Scenario("awsKmsDiscovery",
                require(defaultCmm(awsKmsKeyring(kms.symmetricKeyArn()))),
                null,
                List.of(),
                require(defaultCmm(awsKmsDiscoveryKeyring()))));
    }

    private static Keyring awsKmsKeyring(String kmsKeyId) {
        return Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(kmsKeyId).build())
            .build();
    }

    private static Keyring awsKmsMrkKeyring(String kmsKeyId) {
        return Keyring.builder()
            .awsKmsMrk(AwsKmsMrkKeyringConfig.builder().kmsKeyId(kmsKeyId).build())
            .build();
    }

    private static Keyring awsKmsMultiKeyring(String generator, List<String> childKeyIds) {
        return Keyring.builder()
            .awsKmsMultiKeyring(AwsKmsMultiKeyringConfig.builder()
                .generator(generator)
                .kmsKeyIds(childKeyIds)
                .build())
            .build();
    }

    private static Keyring awsKmsMrkMultiKeyring(String generator, List<String> childKeyIds) {
        return Keyring.builder()
            .awsKmsMrkMultiKeyring(AwsKmsMrkMultiKeyringConfig.builder()
                .generator(generator)
                .kmsKeyIds(childKeyIds)
                .build())
            .build();
    }

    private static Keyring awsKmsRsaKeyring(String kmsKeyId, KmsRsaEncryptionAlgorithm algorithm) {
        // No publicKey supplied: the Language_Server fetches it once from KMS via
        // kms:GetPublicKey at construction (design "KMS keyring wiring").
        return Keyring.builder()
            .awsKmsRsa(AwsKmsRsaKeyringConfig.builder()
                .kmsKeyId(kmsKeyId)
                .encryptionAlgorithm(algorithm)
                .build())
            .build();
    }

    private static Keyring awsKmsDiscoveryKeyring() {
        // A plain discovery keyring (no discovery filter): decrypt-only, region
        // resolved from the ambient AWS region the Tests configured.
        return Keyring.builder()
            .awsKmsDiscovery(AwsKmsDiscoveryKeyringConfig.builder().build())
            .build();
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
