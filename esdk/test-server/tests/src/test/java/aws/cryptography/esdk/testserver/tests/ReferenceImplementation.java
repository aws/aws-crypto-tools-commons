package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureDeclarations;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;

import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Resolves the run's <strong>reference implementation</strong> — the language
 * whose Language_Server plays the immaterial producer side of single-sided
 * Tests — and composes the decrypt-side rows: the reference produces each
 * message and every configured target decrypts it, one row per target (N rows)
 * instead of the full pairwise matrix (N²). A Test iterates
 * {@link #decryptSide} only when its assertion reads nothing but the decryptor
 * (tamper/truncation rejection, decrypt-side policy enforcement,
 * decrypt-response introspection); a Test whose pairing itself carries signal
 * (round trips, vectors) stays on {@link LanguageServerRegistry#pairs()}.
 *
 * <p>The reference language comes from
 * <b>{@code testserver.referenceImplementation}</b> (system property) or
 * <b>{@code TESTSERVER_REFERENCE_IMPLEMENTATION}</b> (environment
 * variable), defaulting to {@code java}; the orchestrator passes its validated
 * {@code referenceImplementation} argument through the property.
 *
 * <p><b>Capability substitution:</b> when the reference language does not
 * declare a Feature (or raw-RSA padding scheme) a scenario requires, the first
 * capable target in configuration order substitutes as that scenario's
 * reference — a capable decryptor is never skipped because the reference cannot
 * produce its message, and an incapable reference never produces one. A
 * substituted row is annotated in its display name ({@code ref(sub):…}). When
 * no configured language is capable, rows are still composed (with the
 * reference language's target, or the primary target when it has none) so
 * every row feature-gates visibly instead of vanishing from the case list.
 */
public final class ReferenceImplementation {

    /** Runtime-config key: the reference implementation's language. */
    public static final String REFERENCE_PROPERTY = "testserver.referenceImplementation";
    public static final String REFERENCE_ENV = "TESTSERVER_REFERENCE_IMPLEMENTATION";

    /** The default reference language, mirroring the orchestrator's default. */
    static final String DEFAULT_REFERENCE_LANGUAGE = "java";

    private ReferenceImplementation() {
    }

    /** The decrypt-side rows for a scenario requiring {@code features}. */
    public static List<ReferencePair> decryptSide(Set<String> features) {
        return decryptSide(features, Set.of());
    }

    /**
     * The decrypt-side rows for a scenario requiring {@code features} and the
     * raw-RSA {@code paddings}.
     */
    public static List<ReferencePair> decryptSide(
            Set<String> features, Set<PaddingScheme> paddings) {
        return decryptSide(features, paddings, LanguageServerRegistry.shared(),
            FeatureDeclarations.shared(), configuredReferenceLanguage());
    }

    /**
     * Rows against explicit registries; package-private so unit tests can
     * exercise the composition without touching the JVM-wide singletons or
     * system properties — mirroring {@link FeatureGate}.
     */
    static List<ReferencePair> decryptSide(
            Set<String> features, Set<PaddingScheme> paddings,
            LanguageServerRegistry registry, FeatureDeclarations declarations,
            String referenceLanguage) {
        LanguageServerTarget reference =
            referenceSource(features, paddings, registry, declarations, referenceLanguage);
        boolean substituted = !reference.language().equals(referenceLanguage);
        List<ReferencePair> rows = new ArrayList<>(registry.targets().size());
        for (LanguageServerTarget decryptTarget : registry.targets()) {
            rows.add(new ReferencePair(reference, decryptTarget, substituted));
        }
        return rows;
    }

    /**
     * The scenario's reference source: the reference language's first target
     * when that language declares every required Feature and padding, otherwise
     * the first capable target in configuration order; with no capable target,
     * the reference language's target (or the primary) so the composed rows
     * feature-gate visibly.
     */
    static LanguageServerTarget referenceSource(
            Set<String> features, Set<PaddingScheme> paddings,
            LanguageServerRegistry registry, FeatureDeclarations declarations,
            String referenceLanguage) {
        List<LanguageServerTarget> candidates = new ArrayList<>();
        for (LanguageServerTarget target : registry.targets()) {
            if (target.language().equals(referenceLanguage)) {
                candidates.add(target);
                break;
            }
        }
        for (LanguageServerTarget target : registry.targets()) {
            if (!candidates.contains(target)) {
                candidates.add(target);
            }
        }
        for (LanguageServerTarget candidate : candidates) {
            if (isCapable(declarations, candidate, features, paddings)) {
                return candidate;
            }
        }
        return candidates.get(0);
    }

    /** Whether {@code target} declares every required Feature and padding. */
    private static boolean isCapable(FeatureDeclarations declarations, LanguageServerTarget target,
            Set<String> features, Set<PaddingScheme> paddings) {
        for (String feature : features) {
            if (!declarations.isSupported(
                    target.language(), target.majorVersion(), target.repo(), feature)) {
                return false;
            }
        }
        for (PaddingScheme padding : paddings) {
            if (!declarations.supportsRawRsaPadding(
                    target.language(), target.majorVersion(), target.repo(), padding.getValue())) {
                return false;
            }
        }
        return true;
    }

    /**
     * The configured reference language: system property, then environment,
     * then {@value #DEFAULT_REFERENCE_LANGUAGE}.
     */
    static String configuredReferenceLanguage() {
        String property = System.getProperty(REFERENCE_PROPERTY);
        if (property != null && !property.isBlank()) {
            return referenceLanguage(property);
        }
        return referenceLanguage(System.getenv(REFERENCE_ENV));
    }

    /** {@code raw} trimmed, or the default when null/blank; package-private for unit tests. */
    static String referenceLanguage(String raw) {
        return raw == null || raw.isBlank() ? DEFAULT_REFERENCE_LANGUAGE : raw.trim();
    }
}
