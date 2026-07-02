package aws.cryptography.esdk.testserver.server.config;

import aws.cryptography.esdk.testserver.server.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RequiredEncryptionContextCmmConfig;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.registry.RealEsdkClient;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
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
 * <p>Scope note (this pass): the offline-capable variants used by the round-trip
 * tests — Raw AES, Raw RSA, Multi, and the Default / RequiredEncryptionContext
 * CMMs — are fully wired. The AWS KMS keyrings are constructed (no network at
 * construction; network only on encrypt/decrypt). The Caching CMM and the KMS
 * RSA / discovery keyrings are not wired in this pass and cause a construction
 * failure (GenericServerError) if requested.
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
            // Constructs the KMS client but performs no network call until use.
            return materialProviders.CreateAwsKmsMultiKeyring(
                CreateAwsKmsMultiKeyringInput.builder().generator(awsKms.getKmsKeyId()).build());
        }
        if (awsKmsMrk != null) {
            return materialProviders.CreateAwsKmsMrkMultiKeyring(
                CreateAwsKmsMrkMultiKeyringInput.builder().generator(awsKmsMrk.getKmsKeyId()).build());
        }
        if (awsKmsMulti != null) {
            CreateAwsKmsMultiKeyringInput.Builder builder = CreateAwsKmsMultiKeyringInput.builder();
            if (awsKmsMulti.getGenerator() != null) {
                builder.generator(awsKmsMulti.getGenerator());
            }
            if (awsKmsMulti.hasKmsKeyIds()) {
                builder.kmsKeyIds(new ArrayList<>(awsKmsMulti.getKmsKeyIds()));
            }
            return materialProviders.CreateAwsKmsMultiKeyring(builder.build());
        }
        throw new UnsupportedOperationException(
            "Keyring variant is not wired in this pass of the ESDK TestServer");
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
