package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.FeatureGate;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ESDK-side thin wrapper over the shared {@link FeatureGate} that preserves the
 * modeled {@link PaddingScheme} type at ESDK call sites. The shared gate takes
 * scheme names as opaque strings so it never imports a per-SDK generated enum;
 * this wrapper converts on the way in.
 *
 * <p>Every gate that only cites Features (no padding schemes) can call the
 * shared {@link FeatureGate#require} directly; this wrapper exists only for the
 * padding sub-gate.
 */
public final class EsdkFeatureGate {

    private EsdkFeatureGate() {
    }

    /**
     * Gate the calling Test execution on both combination languages supporting
     * every raw-RSA padding scheme in {@code paddingSchemes}; see
     * {@link FeatureGate#requireRawRsaPaddings(Set, TargetPair)}.
     */
    public static void requireRawRsaPaddings(
            Set<PaddingScheme> paddingSchemes, TargetPair combination) {
        FeatureGate.requireRawRsaPaddings(
            paddingSchemes.stream()
                .map(PaddingScheme::getValue)
                .collect(Collectors.toUnmodifiableSet()),
            combination);
    }
}
