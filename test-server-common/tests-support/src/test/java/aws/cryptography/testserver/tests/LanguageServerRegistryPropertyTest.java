package aws.cryptography.testserver.tests;

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
 * For any set of targets, formatting them as the {@code testserver.targets}
 * string and parsing it back through {@link LanguageServerRegistry} yields the
 * same targets in the same order, and the registry's pairwise matrix is exactly
 * the full (encrypt, decrypt) product of those targets — n-squared pairs,
 * including every same-target pair.
 *
 * <p>Parsing goes through the public {@link LanguageServerRegistry#parse} seam,
 * so no system properties or launched servers are involved.
 */
class LanguageServerRegistryPropertyTest {

    @Property(tries = 100)
    void targetsRoundTripAndMatrixIsFullPairwiseProduct(
            @ForAll("targetLists") List<LanguageServerTarget> targets) {
        // testserver.targets format: language:major:repo=url, comma-separated.
        String targetsProperty = targets.stream()
            .map(t -> t.language() + ":" + t.majorVersion() + ":" + t.repo() + "=" + t.endpoint())
            .collect(Collectors.joining(","));

        LanguageServerRegistry registry = LanguageServerRegistry.parse(targetsProperty);

        assertEquals(targets, registry.targets(),
            "targets did not round-trip through " + LanguageServerRegistry.TARGETS_PROPERTY
                + ": " + targetsProperty);

        List<TargetPair> pairs = registry.pairs();
        int n = targets.size();
        assertEquals(n * n, pairs.size(),
            "matrix size must be the square of the target count (" + n + ")");

        Set<TargetPair> expected = new HashSet<>();
        for (LanguageServerTarget encrypt : targets) {
            for (LanguageServerTarget decrypt : targets) {
                expected.add(new TargetPair(encrypt, decrypt));
            }
        }
        assertEquals(expected, new HashSet<>(pairs),
            "matrix must cover every ordered (encrypt, decrypt) combination exactly");
        for (LanguageServerTarget target : targets) {
            assertTrue(pairs.contains(new TargetPair(target, target)),
                "matrix must include the same-target pair for " + target.label());
        }
    }

    @Provide
    Arbitrary<List<LanguageServerTarget>> targetLists() {
        Arbitrary<String> languageNames =
            Arbitraries.strings().withCharRange('a', 'z').ofMinLength(2).ofMaxLength(8);
        Arbitrary<Integer> majorVersions = Arbitraries.integers().between(1, 9);
        Arbitrary<Tuple.Tuple2<String, Integer>> targetKeys =
            Combinators.combine(languageNames, majorVersions).as(Tuple::of);
        return targetKeys.list().ofMinSize(1).ofMaxSize(5)
            .map(LanguageServerRegistryPropertyTest::toDistinctTargets);
    }

    /**
     * Deduplicate generated (language, majorVersion) keys by label — the registry
     * rejects duplicate identities — and give each surviving target a distinct
     * endpoint port, preserving generation order.
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
}
