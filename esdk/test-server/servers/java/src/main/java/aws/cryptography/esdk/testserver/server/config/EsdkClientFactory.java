package aws.cryptography.esdk.testserver.server.config;

import aws.cryptography.esdk.testserver.server.model.AwsKmsDiscoveryKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RequiredEncryptionContextCmmConfig;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.registry.RealEsdkClient;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsDiscoveryKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;

/**
 * Translates a validated {@link ESDKClientConfig} into a {@link RealEsdkClient}
 * backed by the REAL AWS Encryption SDK for Java plus the AWS Cryptographic
 * Material Providers library (Requirement 3.1). The tagged-union config shapes
 * are walked recursively — a Default/RequiredEncryptionContext CMM, and a Multi
 * keyring whose children are themselves keyrings — mirroring the model's
 * recursive variants (Requirement 2.5).
 *
 * <p>This factory assumes the config has already passed {@link ConfigValidator}
 * (exactly one variant member set at each polymorphic node). Any failure to
 * build a real client — an unsupported variant in this pass, or an input the
 * material providers / ESDK reject — is surfaced as a thrown exception; the
 * {@code CreateClient} handler maps that to a {@code GenericServerError} and
 * leaves the registry unchanged (Requirement 3.6).
 *
 * <p>Scope note: the offline-capable variants used by the offline round-trip
 * tests — Raw AES, Raw RSA, Multi, and the Default / RequiredEncryptionContext
 * CMMs — are fully wired. All five AWS KMS keyring variants are also fully wired
 * (task 15.3): {@code AwsKms} (single symmetric key), {@code AwsKmsMrk} (single
 * multi-region key), {@code AwsKmsMultiKeyring} (generator + child keys),
 * {@code AwsKmsRsa} (asymmetric RSA key), and {@code AwsKmsDiscovery} (discovery
 * keyring). Every KMS keyring is <em>constructed</em> without a network call —
 * the KMS client is built eagerly but is not invoked — so {@code CreateClient}
 * stays offline; the real AWS KMS calls happen only on {@code Encrypt}/{@code
 * Decrypt} (Requirements 14.1, 14.3, 14.4, 14.14). The single exception is the
 * {@code AwsKmsRsa} keyring when the modeled config omits the RSA public key: in
 * that case the factory fetches it once via {@code kms:GetPublicKey} at
 * construction (a network call the design explicitly permits at
 * {@code CreateClient} time); supplying {@code publicKey} in the config keeps
 * construction fully offline. The Caching CMM remains unwired and causes a
 * construction failure (GenericServerError) if requested (Requirement 3.6).
 */
public final class EsdkClientFactory {

    private final MaterialProviders materialProviders;

    public EsdkClientFactory() {
        this.materialProviders = MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    }

    /**
     * Build a configured real ESDK client from the modeled config.
     *
     * @throws RuntimeException if a real client cannot be constructed; the caller
     *     maps this to a {@code GenericServerError} (Requirement 3.6).
     */
    public EsdkClient create(ESDKClientConfig config) {
        CommitmentPolicy commitmentPolicy = toCommitmentPolicy(config.getCommitmentPolicy().getValue());
        Integer maxEdk = config.getMaxEncryptedDataKeys() == null
            ? null
            : Math.toIntExact(config.getMaxEncryptedDataKeys());
        ICryptographicMaterialsManager cmm = buildCmm(config.getCmm());
        return new RealEsdkClient(commitmentPolicy, maxEdk, cmm);
    }

    private ICryptographicMaterialsManager buildCmm(CryptographicMaterialsManager cmm) {
        DefaultCmmConfig defaultCmm = cmm.getDefault();
        RequiredEncryptionContextCmmConfig requiredEc = cmm.getRequiredEncryptionContext();
        CachingCmmConfig caching = cmm.getCaching();

        if (defaultCmm != null) {
            IKeyring keyring = buildKeyring(defaultCmm.getKeyring());
            return materialProviders.CreateDefaultCryptographicMaterialsManager(
                CreateDefaultCryptographicMaterialsManagerInput.builder()
                    .keyring(keyring)
                    .build());
        }
        if (requiredEc != null) {
            ICryptographicMaterialsManager underlying = buildCmm(requiredEc.getUnderlyingCMM());
            return materialProviders.CreateRequiredEncryptionContextCMM(
                CreateRequiredEncryptionContextCMMInput.builder()
                    .underlyingCMM(underlying)
                    .requiredEncryptionContextKeys(
                        new ArrayList<>(requiredEc.getRequiredEncryptionContextKeys()))
                    .build());
        }
        if (caching != null) {
            throw new UnsupportedOperationException(
                "Caching CMM is not wired in this pass of the ESDK TestServer");
        }
        throw new IllegalArgumentException(
            "CryptographicMaterialsManager had no variant member set");
    }

    private IKeyring buildKeyring(Keyring keyring) {
        RawAesKeyringConfig rawAes = keyring.getRawAes();
        RawRsaKeyringConfig rawRsa = keyring.getRawRsa();
        MultiKeyringConfig multi = keyring.getMulti();
        AwsKmsKeyringConfig awsKms = keyring.getAwsKms();
        AwsKmsMrkKeyringConfig awsKmsMrk = keyring.getAwsKmsMrk();
        AwsKmsMultiKeyringConfig awsKmsMulti = keyring.getAwsKmsMultiKeyring();
        AwsKmsRsaKeyringConfig awsKmsRsa = keyring.getAwsKmsRsa();
        AwsKmsDiscoveryKeyringConfig awsKmsDiscovery = keyring.getAwsKmsDiscovery();

        if (rawAes != null) {
            return materialProviders.CreateRawAesKeyring(
                CreateRawAesKeyringInput.builder()
                    .keyNamespace(rawAes.getKeyNamespace())
                    .keyName(rawAes.getKeyName())
                    .wrappingKey(rawAes.getWrappingKey())
                    .wrappingAlg(AesWrappingAlg.valueOf(rawAes.getWrappingAlg().getValue()))
                    .build());
        }
        if (rawRsa != null) {
            CreateRawRsaKeyringInput.Builder builder = CreateRawRsaKeyringInput.builder()
                .keyNamespace(rawRsa.getKeyNamespace())
                .keyName(rawRsa.getKeyName())
                .paddingScheme(PaddingScheme.valueOf(rawRsa.getPaddingScheme().getValue()));
            if (rawRsa.getPublicKey() != null) {
                builder.publicKey(rawRsa.getPublicKey());
            }
            if (rawRsa.getPrivateKey() != null) {
                builder.privateKey(rawRsa.getPrivateKey());
            }
            return materialProviders.CreateRawRsaKeyring(builder.build());
        }
        if (multi != null) {
            CreateMultiKeyringInput.Builder builder = CreateMultiKeyringInput.builder();
            if (multi.getGenerator() != null) {
                builder.generator(buildKeyring(multi.getGenerator()));
            }
            List<IKeyring> children = new ArrayList<>();
            for (Keyring child : multi.getChildKeyrings()) {
                children.add(buildKeyring(child));
            }
            builder.childKeyrings(children);
            return materialProviders.CreateMultiKeyring(builder.build());
        }
        if (awsKms != null) {
            // Single symmetric KMS key -> the single-key KMS keyring (the faithful
            // mapping for one symmetric key). The KMS client is built eagerly; no
            // network call happens until Encrypt/Decrypt (Requirement 14.1, 14.14).
            CreateAwsKmsKeyringInput.Builder builder = CreateAwsKmsKeyringInput.builder()
                .kmsKeyId(awsKms.getKmsKeyId())
                .kmsClient(kmsClient());
            if (awsKms.hasGrantTokens() && !awsKms.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKms.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsKeyring(builder.build());
        }
        if (awsKmsMrk != null) {
            // Single multi-region key -> the single-key MRK-aware KMS keyring.
            CreateAwsKmsMrkKeyringInput.Builder builder = CreateAwsKmsMrkKeyringInput.builder()
                .kmsKeyId(awsKmsMrk.getKmsKeyId())
                .kmsClient(kmsClient());
            if (awsKmsMrk.hasGrantTokens() && !awsKmsMrk.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKmsMrk.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsMrkKeyring(builder.build());
        }
        if (awsKmsMulti != null) {
            CreateAwsKmsMultiKeyringInput.Builder builder = CreateAwsKmsMultiKeyringInput.builder();
            if (awsKmsMulti.getGenerator() != null) {
                builder.generator(awsKmsMulti.getGenerator());
            }
            if (awsKmsMulti.hasKmsKeyIds()) {
                builder.kmsKeyIds(new ArrayList<>(awsKmsMulti.getKmsKeyIds()));
            }
            if (awsKmsMulti.hasGrantTokens() && !awsKmsMulti.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKmsMulti.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsMultiKeyring(builder.build());
        }
        if (awsKmsRsa != null) {
            return buildAwsKmsRsaKeyring(awsKmsRsa);
        }
        if (awsKmsDiscovery != null) {
            return buildAwsKmsDiscoveryKeyring(awsKmsDiscovery);
        }
        throw new IllegalArgumentException("Keyring had no variant member set");
    }

    /**
     * Build the AWS KMS RSA keyring (Requirement 14.3, 14.4). The keyring needs
     * the RSA <em>public key</em> bytes (for encrypt), the KMS key id/ARN and a KMS
     * client (for decrypt, which calls {@code kms:Decrypt}), and an RSAES-OAEP
     * encryption algorithm mapped from the modeled {@link KmsRsaEncryptionAlgorithm}.
     *
     * <p>Public-key sourcing: if the modeled config carries {@code publicKey}, it
     * is used and construction stays fully offline. Otherwise the factory fetches
     * it once via {@code kms:GetPublicKey} — a network call the design permits at
     * {@code CreateClient} time (KMS scenarios only run when credentials are
     * present). Either way, no encrypt/decrypt happens at construction.
     */
    private IKeyring buildAwsKmsRsaKeyring(AwsKmsRsaKeyringConfig config) {
        KmsClient kmsClient = kmsClient();
        ByteBuffer publicKey = config.getPublicKey();
        if (publicKey == null) {
            // Fetch the RSA public key once from KMS (network call at construction).
            publicKey = kmsClient.getPublicKey(
                    GetPublicKeyRequest.builder().keyId(config.getKmsKeyId()).build())
                .publicKey()
                .asByteBuffer();
        }
        CreateAwsKmsRsaKeyringInput.Builder builder = CreateAwsKmsRsaKeyringInput.builder()
            .kmsKeyId(config.getKmsKeyId())
            .publicKey(publicKey)
            .encryptionAlgorithm(toEncryptionAlgorithmSpec(config.getEncryptionAlgorithm()))
            .kmsClient(kmsClient);
        if (config.hasGrantTokens() && !config.getGrantTokens().isEmpty()) {
            builder.grantTokens(new ArrayList<>(config.getGrantTokens()));
        }
        return materialProviders.CreateAwsKmsRsaKeyring(builder.build());
    }

    /**
     * Build the AWS KMS discovery keyring (Requirement 14.3, 14.4). A discovery
     * keyring is decrypt-only: it needs a KMS client (its region comes from the
     * ambient AWS region / credentials the online Tests supply) and, optionally, a
     * discovery filter scoping decrypt to a partition + account ids. On the
     * round-trip it pairs with an encrypting KMS keyring on the encrypt leg.
     */
    private IKeyring buildAwsKmsDiscoveryKeyring(AwsKmsDiscoveryKeyringConfig config) {
        CreateAwsKmsDiscoveryKeyringInput.Builder builder = CreateAwsKmsDiscoveryKeyringInput.builder()
            .kmsClient(kmsClient());
        aws.cryptography.esdk.testserver.server.model.DiscoveryFilter modeledFilter =
            config.getDiscoveryFilter();
        if (modeledFilter != null) {
            builder.discoveryFilter(
                software.amazon.cryptography.materialproviders.model.DiscoveryFilter.builder()
                    .partition(modeledFilter.getPartition())
                    .accountIds(new ArrayList<>(modeledFilter.getAccountIds()))
                    .build());
        }
        if (config.hasGrantTokens() && !config.getGrantTokens().isEmpty()) {
            builder.grantTokens(new ArrayList<>(config.getGrantTokens()));
        }
        return materialProviders.CreateAwsKmsDiscoveryKeyring(builder.build());
    }

    /**
     * Construct an AWS KMS client. Building the client performs no network call;
     * the region is resolved from the ambient AWS region provider chain (the
     * {@code AWS_REGION} / configured region the online KMS Tests supply). Key-ARN
     * based keyrings encode their own region, but the client is supplied so
     * discovery (which has no key ARN) and RSA (GetPublicKey) can reach KMS.
     */
    private static KmsClient kmsClient() {
        return KmsClient.create();
    }

    private static EncryptionAlgorithmSpec toEncryptionAlgorithmSpec(
        KmsRsaEncryptionAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException(
                "AwsKmsRsa keyring requires an encryptionAlgorithm (RSAES_OAEP_SHA_1 "
                    + "or RSAES_OAEP_SHA_256)");
        }
        return switch (algorithm.getValue()) {
            case "RSAES_OAEP_SHA_1" -> EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1;
            case "RSAES_OAEP_SHA_256" -> EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;
            default -> throw new IllegalArgumentException(
                "Unknown KMS RSA encryption algorithm: " + algorithm.getValue());
        };
    }

    private static CommitmentPolicy toCommitmentPolicy(String value) {
        return switch (value) {
            case "FORBID_ENCRYPT_ALLOW_DECRYPT" -> CommitmentPolicy.ForbidEncryptAllowDecrypt;
            case "REQUIRE_ENCRYPT_ALLOW_DECRYPT" -> CommitmentPolicy.RequireEncryptAllowDecrypt;
            case "REQUIRE_ENCRYPT_REQUIRE_DECRYPT" -> CommitmentPolicy.RequireEncryptRequireDecrypt;
            default -> throw new IllegalArgumentException("Unknown commitment policy: " + value);
        };
    }
}
