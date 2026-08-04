package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.util.Optional;
import java.util.Set;

/**
 * The keyring a keyring-agnostic conformance Test produces its message with. Such a Test's
 * assertion (frame/header/footer/commitment/signature tampering, region ordering, policy
 * enforcement) is independent of the keyring — the keyring is only the vehicle — so the Test runs
 * ONCE, under {@link #negotiate} the single keyring both endpoints support. Raw-AES is preferred
 * (offline, no KMS); the hierarchical keyring is the fallback and the one the native Rust ESDK
 * supports, since it declares only {@code hierarchical}. A pair whose languages share no keyring
 * is a visible skip.
 *
 * <p>Tests that assert something keyring-specific (the Raw-AES EDK provider-info layout) build
 * their keyring directly instead and are correctly skipped where it is unsupported.
 */
enum ConformanceKeyring {
    RAW_AES(Set.of("raw-aes")),
    HIERARCHICAL(Set.of("hierarchical"));

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
        return switch (this) {
            case RAW_AES -> EsdkClientConfigs.rawAesWithCommitmentPolicy(policy);
            case HIERARCHICAL -> EsdkClientConfigs.hierarchicalWithCommitmentPolicy(policy);
        };
    }

    @Override
    public String toString() {
        return switch (this) {
            case RAW_AES -> "rawAes";
            case HIERARCHICAL -> "hierarchical";
        };
    }

    /** The keyring both endpoints of {@code pair} support (Raw-AES first), or empty if none. */
    static Optional<ConformanceKeyring> negotiate(EndpointPair pair) {
        for (ConformanceKeyring keyring : values()) {
            if (keyring.supportedBy(pair)) {
                return Optional.of(keyring);
            }
        }
        return Optional.empty();
    }

    private boolean supportedBy(EndpointPair pair) {
        FeatureDeclarations declarations = FeatureDeclarations.shared();
        for (String feature : features) {
            if (!declarations.isSupported(pair.encryptTarget().language(), feature)
                    || !declarations.isSupported(pair.decryptTarget().language(), feature)) {
                return false;
            }
        }
        return true;
    }
}
