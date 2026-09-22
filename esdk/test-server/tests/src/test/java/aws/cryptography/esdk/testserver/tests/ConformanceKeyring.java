package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureDeclarations;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.Optional;
import java.util.Set;

/**
 * The keyring a keyring-agnostic conformance Test produces its message with. Such a Test's
 * assertion (frame/header/footer/commitment/signature tampering, region ordering, policy
 * enforcement) is independent of the keyring — the keyring is only the vehicle — so the Test runs
 * under Raw-AES, the offline keyring every language supports (the native Rust ESDK builds it
 * through the Dafny MPL). A pair whose languages do not both support Raw-AES is a visible skip.
 *
 * <p>Tests that assert something keyring-specific (the Raw-AES EDK provider-info layout) build
 * their keyring directly instead and are correctly skipped where it is unsupported.
 */
enum ConformanceKeyring {
    RAW_AES(Set.of("raw-aes"));

    private final Set<String> features;

    ConformanceKeyring(Set<String> features) {
        this.features = features;
    }

    /** The Feature(s) both languages of a combination must support to run this keyring. */
    Set<String> features() {
        return features;
    }

    /** The client config for this keyring under {@code policy}. */
    ESDKClientConfig config(ESDKCommitmentPolicy policy) {
        return EsdkClientConfigs.rawAesWithCommitmentPolicy(policy);
    }

    @Override
    public String toString() {
        return "rawAes";
    }

    /** Raw-AES when both endpoints of {@code pair} support it, otherwise empty. */
    static Optional<ConformanceKeyring> negotiate(TargetPair pair) {
        return RAW_AES.supportedBy(pair) ? Optional.of(RAW_AES) : Optional.empty();
    }

    private boolean supportedBy(TargetPair pair) {
        FeatureDeclarations declarations = FeatureDeclarations.shared();
        LanguageServerTarget encrypt = pair.encryptTarget();
        LanguageServerTarget decrypt = pair.decryptTarget();
        for (String feature : features) {
            if (!declarations.isSupported(
                        encrypt.language(), encrypt.majorVersion(), encrypt.repo(), feature)
                    || !declarations.isSupported(
                        decrypt.language(), decrypt.majorVersion(), decrypt.repo(), feature)) {
                return false;
            }
        }
        return true;
    }
}
