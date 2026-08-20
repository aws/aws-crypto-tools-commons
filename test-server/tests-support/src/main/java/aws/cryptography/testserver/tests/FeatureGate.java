package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.opentest4j.TestAbortedException;

/**
 * The Feature gate a Feature-associated Test invokes <em>first in its test
 * body</em>, before any Language_Server operation, to associate the execution
 * with one or more Features from the Feature_Catalog (Requirement 9.1).
 *
 * <p>Decisions are made solely from the {@link FeatureDeclarations} runtime
 * registry (Requirement 9.3), in this order:
 * <ol>
 *   <li>Every required Feature must be defined by the Feature_Catalog. An
 *       unknown Feature is a <b>test failure</b> ({@link AssertionError} naming
 *       the Test and the unknown Feature) — never a pass or a skip
 *       (Requirement 9.11). This check runs first.</li>
 *   <li>If any language in the combination declares any required Feature
 *       unsupported, the Test is skipped visibly via
 *       {@link TestAbortedException} with the message
 *       {@code feature-gated skip: feature=<f> unsupported by [<languages>]},
 *       naming each gating Feature and exactly the languages declaring it
 *       unsupported (Requirements 9.5, 9.6). No Language_Server operation has
 *       been invoked yet.</li>
 *   <li>A missing declaration — no registry configured, no declaration for a
 *       combination language, or no value for a (language, Feature) pair — is
 *       a <b>configuration failure</b> ({@link IllegalStateException} from the
 *       registry): support is never assumed (Requirement 9.3).</li>
 * </ol>
 *
 * <p>When every combination language declares every required Feature supported,
 * the gate returns normally and the Test executes (Requirement 9.4). Tests with
 * no Feature association simply never call the gate (Requirement 9.7).
 */
public final class FeatureGate {

    private FeatureGate() {
    }

    /**
     * Associate the calling Test execution with {@code features} for
     * {@code combination}; call first in the test body, before any
     * Language_Server operation.
     *
     * @throws AssertionError if any Feature is not defined by the
     *     Feature_Catalog (Requirement 9.11)
     * @throws TestAbortedException if any combination language declares any
     *     required Feature unsupported (Requirements 9.5, 9.6)
     * @throws IllegalStateException if a required declaration is missing — a
     *     configuration error, never assumed support (Requirement 9.3)
     */
    public static void require(Set<String> features, TargetPair combination) {
        require(features, combination, FeatureDeclarations.shared());
    }

    /**
     * Gate against an explicit registry. Package-private so unit tests can
     * exercise the decision logic without touching the JVM-wide singleton or
     * system properties — mirroring {@link FeatureDeclarations#parse}.
     */
    static void require(Set<String> features, TargetPair combination, FeatureDeclarations declarations) {
        // Deterministic ordering for messages, whatever Set implementation the
        // caller hands us.
        List<String> requiredFeatures = List.copyOf(new TreeSet<>(features));

        // 1. Unknown Feature vs the catalog is a test FAILURE, checked before
        //    any declaration lookup (Requirement 9.11). An unconfigured catalog
        //    surfaces here as the registry's configuration error.
        List<String> catalog = declarations.catalog();
        for (String feature : requiredFeatures) {
            if (!catalog.contains(feature)) {
                throw new AssertionError(
                    "Test " + callingTest() + " is associated with unknown Feature '" + feature
                        + "': the Feature_Catalog defines " + catalog
                        + " (Requirement 9.11 — never recorded as passed or skipped)");
            }
        }

        // 2. Collect, per gating Feature, exactly the combination languages
        //    declaring it unsupported. A missing declaration propagates as the
        //    registry's configuration error (Requirement 9.3).
        List<String> languages = combinationLanguages(combination);
        Map<String, List<String>> unsupportedByFeature = new LinkedHashMap<>();
        for (String feature : requiredFeatures) {
            List<String> unsupporting = new ArrayList<>();
            for (String language : languages) {
                if (!declarations.isSupported(language, feature)) {
                    unsupporting.add(language);
                }
            }
            if (!unsupporting.isEmpty()) {
                unsupportedByFeature.put(feature, unsupporting);
            }
        }

        // 3. Any gating Feature ⇒ visible skip before any Language_Server
        //    operation (Requirements 9.5, 9.6).
        if (!unsupportedByFeature.isEmpty()) {
            throw new TestAbortedException(skipMessage(unsupportedByFeature));
        }
    }

    /**
     * Gate the calling Test execution on both combination languages supporting
     * every raw-RSA padding scheme in {@code paddingSchemes}; call after
     * {@link #require} (which gates the {@code raw-rsa} Feature itself), before
     * any Language_Server operation. A language whose Feature_Declaration
     * carries no {@code rawRsaPaddingSchemes} supports every scheme, so an
     * empty registry never skips. Type safety of scheme names plays
     * the Feature_Catalog's role: there is no unknown-scheme case.
     *
     * @throws TestAbortedException if any combination language declares any
     *     required scheme outside its supported subset, with the message
     *     {@code padding-gated skip: rawRsaPadding=<scheme> unsupported by
     *     [<languages>]}, one clause per gating scheme
     */
    public static void requireRawRsaPaddings(
            Set<String> paddingSchemes, TargetPair combination) {
        requireRawRsaPaddings(paddingSchemes, combination, FeatureDeclarations.shared());
    }

    /** Padding gate against an explicit registry; package-private for unit tests. */
    static void requireRawRsaPaddings(
            Set<String> paddingSchemes, TargetPair combination,
            FeatureDeclarations declarations) {
        List<String> required = paddingSchemes.stream()
            .sorted(Comparator.naturalOrder())
            .toList();

        List<String> languages = combinationLanguages(combination);
        Map<String, List<String>> unsupportedByScheme = new LinkedHashMap<>();
        for (String scheme : required) {
            List<String> unsupporting = new ArrayList<>();
            for (String language : languages) {
                if (!declarations.supportsRawRsaPadding(language, scheme)) {
                    unsupporting.add(language);
                }
            }
            if (!unsupporting.isEmpty()) {
                unsupportedByScheme.put(scheme, unsupporting);
            }
        }

        if (!unsupportedByScheme.isEmpty()) {
            StringBuilder message = new StringBuilder("padding-gated skip: ");
            boolean first = true;
            for (Map.Entry<String, List<String>> gating : unsupportedByScheme.entrySet()) {
                if (!first) {
                    message.append("; ");
                }
                first = false;
                message.append("rawRsaPadding=").append(gating.getKey())
                    .append(" unsupported by [")
                    .append(String.join(", ", gating.getValue())).append(']');
            }
            throw new TestAbortedException(message.toString());
        }
    }

    /** Distinct combination languages, encrypt target first. */
    private static List<String> combinationLanguages(TargetPair combination) {
        LinkedHashSet<String> languages = new LinkedHashSet<>();
        languages.add(combination.encryptTarget().language());
        languages.add(combination.decryptTarget().language());
        return List.copyOf(languages);
    }

    /**
     * {@code feature-gated skip: feature=<f> unsupported by [<languages>]},
     * one clause per gating Feature.
     */
    private static String skipMessage(Map<String, List<String>> unsupportedByFeature) {
        StringBuilder message = new StringBuilder("feature-gated skip: ");
        boolean first = true;
        for (Map.Entry<String, List<String>> gating : unsupportedByFeature.entrySet()) {
            if (!first) {
                message.append("; ");
            }
            first = false;
            message.append("feature=").append(gating.getKey())
                .append(" unsupported by [").append(String.join(", ", gating.getValue())).append(']');
        }
        return message.toString();
    }

    /** The calling Test, for the unknown-Feature failure message. */
    private static String callingTest() {
        return StackWalker.getInstance().walk(frames -> frames
            .filter(frame -> !frame.getClassName().equals(FeatureGate.class.getName()))
            .findFirst()
            .map(frame -> frame.getClassName() + "#" + frame.getMethodName())
            .orElse("<unknown Test>"));
    }
}
