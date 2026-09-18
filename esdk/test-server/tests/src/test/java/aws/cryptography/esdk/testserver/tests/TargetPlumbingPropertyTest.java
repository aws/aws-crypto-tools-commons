package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;

/**
 * Property 12: Target plumbing round-trips and the matrix is the full pairwise
 * product.
 *
 * <p><em>For any</em> generated set of (language, majorVersion, endpoint)
 * targets and per-language feature declarations: formatting them as the
 * {@code esdk.testserver.targets} and {@code esdk.testserver.features}
 * properties and parsing them back yields the same targets and declarations;
 * and the generated cross-language matrix is exactly the full pairwise
 * (encrypt, decrypt) product of the targets, including every same-target pair,
 * so its size is the square of the target count.
 *
 * <p>The formats mirrored by {@link #formatTargets} / {@link #formatFeatures}
 * are the design's normative property contract (the same contract the
 * orchestrator's formatters implement): targets as a {@code lang:major=url}
 * CSV and features as a {@code lang:feat=bool[;feat=bool…]} CSV. Parsing goes
 * through the Tests-side registries' package-private seams
 * ({@link LanguageServerRegistry#parse} and {@link FeatureDeclarations#parse}),
 * so no system properties, singleton state, or Language_Server are involved.
 *
 * <p>Harness-plumbing (meta) scope: like {@link FeatureDeclarationsTest} and
 * {@link FeatureGateTest}, this test lives beside the registries it exercises
 * (their seams are package-private) rather than in the {@code meta} subpackage,
 * and is not fanned across the target matrix.
 *
 * <p><b>Validates: Requirements 9.3, 10.2, 10.3</b>
 */
class TargetPlumbingPropertyTest {

    // Feature: test-server-factoring, Property 12: Target plumbing round-trips and the matrix is the full pairwise product
    @Property(tries = 100)
    void targetPlumbingRoundTripsAndMatrixIsFullPairwiseProduct(@ForAll("fixtures") Fixture fixture) {
        List<LanguageServerTarget> targets = fixture.targets();
        Map<String, Map<String, Boolean>> featuresByLanguage = fixture.featuresByLanguage();

        // ---- format per the normative runtime-property formats -------------
        String targetsProperty = formatTargets(targets);
        String featuresProperty = formatFeatures(featuresByLanguage);

        // ---- parse back through the Tests-side registries -------------------
        LanguageServerRegistry registry = LanguageServerRegistry.parse(targetsProperty);
        FeatureDeclarations declarations = FeatureDeclarations.parse(featuresProperty, null);

        // Round trip: every (language, majorVersion, endpoint) target survives,
        // in order (Requirement 10.2 — targets are located exclusively through
        // the runtime property).
        assertEquals(targets, registry.targets(),
            "targets did not round-trip through " + LanguageServerRegistry.TARGETS_PROPERTY
                + ": " + targetsProperty);

        // Round trip: every (language, Feature) boolean declaration survives
        // (Requirement 9.3 — support is determined solely from the declarations).
        assertEquals(featuresByLanguage.keySet(), declarations.languages(),
            "declared languages did not round-trip through "
                + FeatureDeclarations.FEATURES_PROPERTY + ": " + featuresProperty);
        featuresByLanguage.forEach((language, byFeature) ->
            byFeature.forEach((feature, supported) ->
                assertEquals(supported, declarations.isSupported(language, feature),
                    "declaration did not round-trip for (" + language + ", " + feature
                        + ") through: " + featuresProperty)));

        // Matrix: exactly the full pairwise (encrypt, decrypt) product,
        // including every same-target pair — size = square of the target count
        // (Requirement 10.3).
        List<EndpointPair> pairs = registry.pairs();
        int n = targets.size();
        assertEquals(n * n, pairs.size(),
            "matrix size must be the square of the target count (" + n + ")");

        Set<EndpointPair> expected = new HashSet<>();
        for (LanguageServerTarget encrypt : targets) {
            for (LanguageServerTarget decrypt : targets) {
                expected.add(new EndpointPair(encrypt, decrypt));
            }
        }
        assertEquals(expected, new HashSet<>(pairs),
            "matrix must cover every ordered (encrypt, decrypt) combination exactly");
        for (LanguageServerTarget target : targets) {
            assertTrue(pairs.contains(new EndpointPair(target, target)),
                "matrix must include the same-target pair for " + target.label());
        }
    }

    // ------------------------------------------------------------- formatting

    /** The normative {@code esdk.testserver.targets} format: {@code lang:major:repo=url} CSV. */
    private static String formatTargets(List<LanguageServerTarget> targets) {
        return targets.stream()
            .map(t -> t.language() + ":" + t.majorVersion() + ":" + t.repository() + "=" + t.endpoint())
            .collect(Collectors.joining(","));
    }

    /**
     * The normative {@code esdk.testserver.features} format:
     * {@code lang:feat=bool[;feat=bool…]} CSV.
     */
    private static String formatFeatures(Map<String, Map<String, Boolean>> featuresByLanguage) {
        return featuresByLanguage.entrySet().stream()
            .map(language -> language.getKey() + ":" + language.getValue().entrySet().stream()
                .map(feature -> feature.getKey() + "=" + feature.getValue())
                .collect(Collectors.joining(";")))
            .collect(Collectors.joining(","));
    }

    // ------------------------------------------------------------- generators

    /**
     * A generated plumbing fixture: targets with unique (language, majorVersion)
     * tuples and distinct endpoints, plus a non-empty feature boolean map for
     * every distinct target language.
     */
    record Fixture(
        List<LanguageServerTarget> targets,
        Map<String, Map<String, Boolean>> featuresByLanguage) {
    }

    @Provide
    Arbitrary<Fixture> fixtures() {
        Arbitrary<String> languageNames =
            Arbitraries.strings().withCharRange('a', 'z').ofMinLength(2).ofMaxLength(8);
        Arbitrary<Integer> majorVersions = Arbitraries.integers().between(1, 9);
        Arbitrary<Tuple.Tuple2<String, Integer>> targetKeys =
            Combinators.combine(languageNames, majorVersions).as(Tuple::of);

        Arbitrary<List<LanguageServerTarget>> targetLists = targetKeys.list()
            .ofMinSize(1).ofMaxSize(5)
            .map(TargetPlumbingPropertyTest::toDistinctTargets);

        return targetLists.flatMap(targets -> {
            List<String> languages = targets.stream()
                .map(LanguageServerTarget::language)
                .distinct()
                .toList();
            return featureMaps(languages.size()).map(maps -> {
                Map<String, Map<String, Boolean>> byLanguage = new LinkedHashMap<>();
                for (int i = 0; i < languages.size(); i++) {
                    byLanguage.put(languages.get(i), maps.get(i));
                }
                return new Fixture(targets, byLanguage);
            });
        });
    }

    /**
     * Deduplicate generated (language, majorVersion) keys by target label (the
     * registry rejects duplicate tuples) and assign each surviving target a
     * distinct endpoint port, preserving generation order.
     */
    private static List<LanguageServerTarget> toDistinctTargets(
            List<Tuple.Tuple2<String, Integer>> keys) {
        Map<String, Tuple.Tuple2<String, Integer>> byLabel = new LinkedHashMap<>();
        for (Tuple.Tuple2<String, Integer> key : keys) {
            byLabel.putIfAbsent(key.get1() + "-v" + key.get2(), key);
        }
        List<LanguageServerTarget> targets = new ArrayList<>(byLabel.size());
        int port = 8000;
        for (Tuple.Tuple2<String, Integer> key : byLabel.values()) {
            targets.add(new LanguageServerTarget(
                key.get1(), key.get2(), "repo-" + key.get1(),
                URI.create("http://127.0.0.1:" + port++)));
        }
        return targets;
    }

    /** One non-empty {@code feature -> supported} map per language. */
    private static Arbitrary<List<Map<String, Boolean>>> featureMaps(int languageCount) {
        Arbitrary<String> featureNames = Arbitraries.strings()
            .withCharRange('a', 'z').withCharRange('A', 'Z')
            .ofMinLength(2).ofMaxLength(10);
        Arbitrary<Map<String, Boolean>> oneLanguage =
            Arbitraries.maps(featureNames, Arbitraries.of(Boolean.TRUE, Boolean.FALSE))
                .ofMinSize(1).ofMaxSize(4);
        return oneLanguage.list().ofSize(languageCount);
    }
}
