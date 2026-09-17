package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.AwsKmsDiscoveryKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.DiscoveryFilter;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.GenericServerError;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Client-construction validation conformance: {@code CreateClient} with an invalid configuration
 * is rejected as a framework {@link GenericServerError} (Requirement 3.6), not silently accepted.
 * A per-server property. Catalog behaviors (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>ENC-005</b> — an invalid maxEncryptedDataKeys (0) is rejected
 *       ({@code spec/client-apis/client.md#initialization}).</li>
 *   <li><b>KEYRING-006</b> — a Raw-AES wrapping key whose length does not match the wrapping suite
 *       is rejected ({@code spec/framework/raw-aes-keyring.md#wrapping-key}).</li>
 *   <li><b>KEYRING-022</b> — a KMS keyring with an empty key id is rejected
 *       ({@code spec/framework/aws-kms/aws-kms-keyring.md#initialization}).</li>
 *   <li><b>KEYRING-043</b> — a discovery filter with an empty partition is rejected
 *       ({@code spec/framework/aws-kms/aws-kms-discovery-keyring.md#initialization}).</li>
 * </ul>
 */
class ClientConfigValidationTests {

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    private static ESDKClientConfig config(Keyring keyring, Long maxEdks) {
        ESDKClientConfig.Builder b = ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder().keyring(keyring).build())
                .build());
        if (maxEdks != null) {
            b.maxEncryptedDataKeys(maxEdks);
        }
        return b.build();
    }

    private static Keyring rawAes(byte[] wrappingKey, AesWrappingAlg alg) {
        return Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace("esdk-test-server")
                .keyName("config-validation-key")
                .wrappingKey(ByteBuffer.wrap(wrappingKey))
                .wrappingAlg(alg)
                .build())
            .build();
    }

    private static void assertCreateRejected(LanguageServerTarget target, ESDKClientConfig config,
                                             String what) {
        assertThrows(GenericServerError.class,
            () -> EsdkOps.createClient(target.endpoint(), config),
            "CreateClient must reject " + what + " (" + target + ")");
    }

    /** ENC-005: maxEncryptedDataKeys of 0 is invalid. */
    @ParameterizedTest(name = "zeroMaxEdksRejected {0}")
    @MethodSource("targets")
    void createClientRejectsZeroMaxEncryptedDataKeys(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        KnownBugGate.gate("create-client-accepts-zero-max-encrypted-data-keys", target,
            () -> assertCreateRejected(target,
                config(rawAes(new byte[32], AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16), 0L),
                "a maxEncryptedDataKeys of 0"));
    }

    /** KEYRING-006: a 16-byte wrapping key does not match the AES-256 wrapping suite. */
    @ParameterizedTest(name = "wrongAesKeyLengthRejected {0}")
    @MethodSource("targets")
    void createClientRejectsMismatchedAesWrappingKeyLength(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        KnownBugGate.gate("raw-aes-wrong-wrapping-key-length-rejected-as-esdk-error", target,
            () -> assertCreateRejected(target,
                config(rawAes(new byte[16], AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16), null),
                "a 16-byte wrapping key for a 256-bit AES wrapping suite"));
    }

    /** KEYRING-022: a KMS keyring with an empty key id is invalid. */
    @ParameterizedTest(name = "emptyKmsKeyIdRejected {0}")
    @MethodSource("targets")
    void createClientRejectsEmptyKmsKeyId(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms"), new EndpointPair(target, target));
        Keyring kms = Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId("").build())
            .build();
        assertCreateRejected(target, config(kms, null), "a KMS keyring with an empty key id");
    }

    /** KEYRING-043: a discovery filter with an empty partition is invalid. */
    @ParameterizedTest(name = "emptyDiscoveryPartitionRejected {0}")
    @MethodSource("targets")
    void createClientRejectsEmptyDiscoveryPartition(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-discovery"), new EndpointPair(target, target));
        Keyring discovery = Keyring.builder()
            .awsKmsDiscovery(AwsKmsDiscoveryKeyringConfig.builder()
                .discoveryFilter(DiscoveryFilter.builder()
                    .partition("")
                    .accountIds(List.of("123456789012"))
                    .build())
                .build())
            .build();
        assertCreateRejected(target, config(discovery, null),
            "a discovery filter with an empty partition");
    }

    /** KEYRING-037: an MRK-aware KMS keyring with an empty key id is invalid. */
    @ParameterizedTest(name = "emptyMrkKeyIdRejected {0}")
    @MethodSource("targets")
    void createClientRejectsEmptyMrkKeyId(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-mrk"), new EndpointPair(target, target));
        Keyring mrk = Keyring.builder()
            .awsKmsMrk(aws.cryptography.esdk.testserver.client.model.AwsKmsMrkKeyringConfig.builder()
                .kmsKeyId("")
                .build())
            .build();
        assertCreateRejected(target, config(mrk, null), "an MRK KMS keyring with an empty key id");
    }

    /** KEYRING-055: a multi-keyring with no generator and no children is invalid. */
    @ParameterizedTest(name = "emptyMultiKeyringRejected {0}")
    @MethodSource("targets")
    void createClientRejectsEmptyMultiKeyring(LanguageServerTarget target) {
        FeatureGate.require(Set.of("multi"), new EndpointPair(target, target));
        Keyring emptyMulti = Keyring.builder()
            .multi(aws.cryptography.esdk.testserver.client.model.MultiKeyringConfig.builder()
                .childKeyrings(List.of())
                .build())
            .build();
        assertCreateRejected(target, config(emptyMulti, null),
            "a multi-keyring with no generator and no child keyrings");
    }

    /** KEYRING-010: a Raw-RSA keyring requires at least one key (public or private). */
    @ParameterizedTest(name = "rawRsaNoKeysRejected {0}")
    @MethodSource("targets")
    void createClientRejectsRawRsaWithNoKeys(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-rsa"), new EndpointPair(target, target));
        Keyring keyring = Keyring.builder()
            .rawRsa(aws.cryptography.esdk.testserver.client.model.RawRsaKeyringConfig.builder()
                .keyNamespace("esdk-test-server")
                .keyName("rsa-no-keys")
                .paddingScheme(aws.cryptography.esdk.testserver.client.model.PaddingScheme.OAEP_SHA256_MGF1)
                .build())
            .build();
        assertCreateRejected(target, config(keyring, null),
            "a Raw-RSA keyring built with neither a public nor a private key");
    }

    /** KEYRING-073: a Raw-AES keyring in the reserved "aws-kms" key namespace is rejected. */
    @ParameterizedTest(name = "reservedNamespaceRejected {0}")
    @MethodSource("targets")
    void createClientRejectsReservedNamespace(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        Keyring keyring = Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace("aws-kms")
                .keyName("reserved-namespace-key")
                .wrappingKey(ByteBuffer.wrap(new byte[32]))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
        KnownBugGate.gate("create-client-accepts-reserved-aws-kms-namespace", target,
            () -> KnownBugGate.gate("raw-aes-reserved-namespace-rejected-as-esdk-error", target,
                () -> assertCreateRejected(target, config(keyring, null),
                    "a Raw-AES keyring in the reserved 'aws-kms' key namespace")));
    }
}
