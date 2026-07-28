package aws.cryptography.esdk.testserver.orchestrator.run;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The complete runtime input a {@link TestRunner} hands to the single
 * {@code Tests} suite (design "Runtime properties handed to the Tests"):
 *
 * <ul>
 *   <li>the launched {@link TestTarget}s → {@code esdk.testserver.targets}
 *       (Requirement 2.2),</li>
 *   <li>each language's Feature_Declaration flattened to booleans →
 *       {@code esdk.testserver.features} (Requirement 9.3; a Feature in
 *       {@code supportedFeatures} becomes {@code true}, one in
 *       {@code unsupportedFeatures} becomes {@code false}),</li>
 *   <li>the Configuration_Set's Feature_Catalog verbatim →
 *       {@code esdk.testserver.featureCatalog}.</li>
 * </ul>
 *
 * <p>All three values derive from the validated merged configuration artifacts;
 * the formatting helpers are static so the orchestrated pipeline (task 9.1) can
 * reuse them. Insertion order is preserved throughout so the properties are
 * deterministic for a given configuration.
 *
 * @param targets        the launched Targets, in launch order
 * @param features       language → (Feature → supported) flattened declarations
 * @param featureCatalog the Feature_Catalog names, in catalog order
 */
public record TestRunInput(
    List<TestTarget> targets,
    Map<String, Map<String, Boolean>> features,
    List<String> featureCatalog
) {
    public TestRunInput {
        targets = List.copyOf(targets);
        // Defensive, order-preserving copies (Map.copyOf does not preserve order).
        Map<String, Map<String, Boolean>> copied = new LinkedHashMap<>();
        features.forEach((language, declaration) ->
            copied.put(language, Collections.unmodifiableMap(new LinkedHashMap<>(declaration))));
        features = Collections.unmodifiableMap(copied);
        featureCatalog = List.copyOf(featureCatalog);
    }

    /**
     * Format targets as the {@code esdk.testserver.targets} value:
     * {@code lang:major=url} CSV, e.g.
     * {@code java:3=http://127.0.0.1:8091,python:4=http://127.0.0.1:8092}.
     */
    public static String formatTargets(List<TestTarget> targets) {
        return targets.stream()
            .map(TestTarget::asPropertyEntry)
            .collect(Collectors.joining(","));
    }

    /**
     * Format flattened declarations as the {@code esdk.testserver.features}
     * value: {@code lang:feat=bool[;feat=bool…]} CSV, e.g.
     * {@code java:streaming=true;MPL=true,python:streaming=true;MPL=true}.
     */
    public static String formatFeatures(Map<String, Map<String, Boolean>> features) {
        return features.entrySet().stream()
            .map(language -> language.getKey() + ":" + language.getValue().entrySet().stream()
                .map(feature -> feature.getKey() + "=" + feature.getValue())
                .collect(Collectors.joining(";")))
            .collect(Collectors.joining(","));
    }

    /**
     * Format the Feature_Catalog as the {@code esdk.testserver.featureCatalog}
     * value: a Feature-name CSV, e.g. {@code streaming,MPL} — the
     * Configuration_Set's {@code features} list verbatim.
     */
    public static String formatFeatureCatalog(List<String> featureCatalog) {
        return String.join(",", featureCatalog);
    }

    /**
     * Flatten one language's Feature_Declaration to booleans, in catalog order:
     * a Feature in {@code supportedFeatures} becomes {@code true}, one in
     * {@code unsupportedFeatures} becomes {@code false}. Requirement 8
     * validation has already established that every catalog Feature appears in
     * exactly one array, so the result covers the whole catalog for a validated
     * declaration. {@code null} arrays are treated as absent (empty).
     */
    public static Map<String, Boolean> flattenDeclaration(
            List<String> featureCatalog,
            List<String> supportedFeatures,
            List<String> unsupportedFeatures) {
        List<String> supported = supportedFeatures == null ? List.of() : supportedFeatures;
        List<String> unsupported = unsupportedFeatures == null ? List.of() : unsupportedFeatures;
        Map<String, Boolean> flattened = new LinkedHashMap<>();
        for (String feature : featureCatalog) {
            if (supported.contains(feature)) {
                flattened.put(feature, Boolean.TRUE);
            } else if (unsupported.contains(feature)) {
                flattened.put(feature, Boolean.FALSE);
            }
        }
        return flattened;
    }
}
