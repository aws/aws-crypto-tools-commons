package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.statistics.Statistics;
import org.opentest4j.TestAbortedException;

/**
 * Property-based Test for the {@link FeatureGate}.
 *
 * <p>For any generated Feature_Catalog, per-language Feature_Declarations,
 * associated Feature set, and target combination: when every language in the
 * combination lists every associated Feature in its {@code supportedFeatures},
 * the gate permits execution; when at least one language lists at least one
 * associated Feature in its {@code unsupportedFeatures}, the gate aborts as
 * skipped before any Language_Server operation, with a message naming each
 * gating Feature and exactly the targets declaring it unsupported; when an
 * associated Feature is not defined by the catalog, the gate raises a failure
 * (never a pass or a skip) naming the unknown Feature; and when a combination
 * language has no declaration available for an associated Feature, the gate
 * raises a configuration failure rather than assuming support.
 *
 * <p>Harness plumbing, not fanned across the target matrix: the gate is a pure
 * decision over the declarations, so this test injects a
 * {@link FeatureDeclarations} registry via the package-private overloads —
 * no live Language_Server, no system properties, no JVM-wide singleton. The
 * generated declaration maps are formatted into the exact
 * {@code testserver.features} / {@code testserver.featureCatalog}
 * string formats and parsed back, so the property also exercises the real
 * parse path the orchestrator-fed properties take.
 */
class FeatureGatePropertyTest {

    // Every generated target shares this (major, repo); only the language
    // varies, so language <-> source identity is 1:1 in this property.
    private static final int MAJOR = 1;
    private static final String REPO = "aws-database-encryption-sdk-dynamodb";

    @Property(tries = 250)
    void featureGateDecidesSolelyFromTheDeclarations(@ForAll("scenarios") Scenario scenario) {
        FeatureDeclarations declarations =
            FeatureDeclarations.parse(scenario.featuresRaw(), scenario.catalogRaw());
        TargetPair combination = scenario.combination();
        Set<String> required = scenario.requiredFeatures();

        // The gate normalizes required Features to natural (sorted) order and the
        // combination to distinct languages, encrypt target first.
        List<String> sortedRequired = List.copyOf(new TreeSet<>(required));
        List<String> combinationLanguages = scenario.combinationLanguages();

        // Expected outcome, derived from the declarations alone,
        // in the gate's specified decision order.

        // (1) A Feature the catalog does not define is a test FAILURE naming the
        //     unknown Feature — never a pass or a skip — checked before any
        //     declaration lookup.
        Optional<String> firstUnknown = sortedRequired.stream()
            .filter(feature -> !scenario.catalog().contains(feature))
            .findFirst();
        if (firstUnknown.isPresent()) {
            Statistics.collect("unknown-feature failure");
            AssertionError failure = assertThrows(AssertionError.class, () ->
                FeatureGate.require(required, combination, declarations));
            assertTrue(failure.getMessage().contains("'" + firstUnknown.get() + "'"),
                "unknown-Feature failure must name the unknown Feature '" + firstUnknown.get()
                    + "': " + failure.getMessage());
            return;
        }

        // (2) Any combination language without a declared support value for any
        //     required Feature is a configuration failure — support is never
        //     assumed.
        boolean missingDeclaration = sortedRequired.stream().anyMatch(feature ->
            combinationLanguages.stream().anyMatch(language -> {
                Map<String, Boolean> byFeature = scenario.declared().get(language);
                return byFeature == null || byFeature.get(feature) == null;
            }));
        if (missingDeclaration) {
            Statistics.collect("missing-declaration configuration failure");
            IllegalStateException failure = assertThrows(IllegalStateException.class, () ->
                FeatureGate.require(required, combination, declarations));
            assertTrue(failure.getMessage().contains("configuration error"),
                "missing declarations must surface as a configuration error: "
                    + failure.getMessage());
            return;
        }

        // (3) Any language declaring any required Feature unsupported gates the
        //     combination: a visible skip whose message names each gating Feature
        //     (sorted order) and exactly the unsupporting languages, encrypt
        //     target first.
        Map<String, List<String>> unsupportedByFeature = new LinkedHashMap<>();
        for (String feature : sortedRequired) {
            List<String> unsupporting = combinationLanguages.stream()
                .filter(language -> !scenario.declared().get(language).get(feature))
                .map(FeatureGatePropertyTest::label)
                .toList();
            if (!unsupporting.isEmpty()) {
                unsupportedByFeature.put(feature, unsupporting);
            }
        }
        if (!unsupportedByFeature.isEmpty()) {
            Statistics.collect("feature-gated skip");
            TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
                FeatureGate.require(required, combination, declarations));
            assertEquals(expectedSkipMessage(unsupportedByFeature), skip.getMessage());
            return;
        }

        // (4) Every combination language declares every required Feature
        //     supported: the gate permits execution.
        Statistics.collect("pass-through");
        assertDoesNotThrow(() -> FeatureGate.require(required, combination, declarations));
    }

    /** The target label the gate names in its skip message: {@code <language>-v<major>}. */
    private static String label(String language) {
        return language + "-v" + MAJOR;
    }

    /**
     * The specified skip message: {@code feature-gated skip: feature=<f>
     * unsupported by [<targets>]}, one clause per gating Feature, joined by
     * {@code "; "}.
     */
    private static String expectedSkipMessage(Map<String, List<String>> unsupportedByFeature) {
        return "feature-gated skip: " + unsupportedByFeature.entrySet().stream()
            .map(gating -> "feature=" + gating.getKey()
                + " unsupported by [" + String.join(", ", gating.getValue()) + "]")
            .collect(Collectors.joining("; "));
    }

    // ------------------------------------------------------------- generators

    /** A language's declared support for one Feature: true, false, or absent. */
    private enum Support { SUPPORTED, UNSUPPORTED, ABSENT }

    /**
     * A fully generated gate input: catalog, per-language declaration maps
     * (formatted into the real runtime-property strings before parsing), the
     * associated Feature set, and the (encrypt, decrypt) combination.
     */
    record Scenario(
        List<String> catalog,
        Map<String, Map<String, Boolean>> declared,
        Set<String> requiredFeatures,
        String encryptLanguage,
        String decryptLanguage) {

        /** The Feature_Catalog in the {@code testserver.featureCatalog} CSV format. */
        String catalogRaw() {
            return String.join(",", catalog);
        }

        /**
         * The declarations in the {@code testserver.features} format:
         * {@code lang:major:repo:feat=bool[;feat=bool…]} entries, comma-separated.
         */
        String featuresRaw() {
            return declared.entrySet().stream()
                .map(source -> source.getKey() + ":" + MAJOR + ":" + REPO + ":"
                    + source.getValue().entrySet().stream()
                        .map(feature -> feature.getKey() + "=" + feature.getValue())
                        .collect(Collectors.joining(";")))
                .collect(Collectors.joining(","));
        }

        TargetPair combination() {
            return new TargetPair(target(encryptLanguage), target(decryptLanguage));
        }

        /** Distinct combination languages, encrypt target first — the gate's view. */
        List<String> combinationLanguages() {
            return encryptLanguage.equals(decryptLanguage)
                ? List.of(encryptLanguage)
                : List.of(encryptLanguage, decryptLanguage);
        }

        private static LanguageServerTarget target(String language) {
            // No live server: the gate must decide before any Language_Server
            // operation, so an unroutable endpoint proves nothing is contacted.
            return new LanguageServerTarget(
                language, MAJOR, REPO, URI.create("http://127.0.0.1:0/" + language));
        }
    }

    @Provide
    Arbitrary<Scenario> scenarios() {
        Arbitrary<String> names =
            Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1).ofMaxLength(6);
        Arbitrary<List<String>> catalogs = names.list().uniqueElements().ofMinSize(1).ofMaxSize(4);
        Arbitrary<List<String>> languageSets = names.list().uniqueElements().ofMinSize(1).ofMaxSize(3);
        return Combinators.combine(catalogs, names, languageSets)
            .flatAs((catalog, unknownSeed, languages) ->
                // '0' is outside the name alphabet, so the uncataloged Feature name
                // can never collide with a catalog Feature.
                assemble(catalog, unknownSeed + "0", languages));
    }

    private static Arbitrary<Scenario> assemble(
            List<String> catalog, String unknownFeature, List<String> languages) {
        // Weight toward declared-supported so pass-throughs and skips stay common
        // while absent declarations (configuration failures) still occur regularly.
        Arbitrary<Support> support = Arbitraries.frequency(
            Tuple.of(6, Support.SUPPORTED),
            Tuple.of(3, Support.UNSUPPORTED),
            Tuple.of(1, Support.ABSENT));
        // Per language: one tri-state per catalog Feature, plus one for the
        // uncataloged name (a declared-but-uncataloged Feature must still FAIL:
        // the catalog check runs before any declaration lookup).
        Arbitrary<List<List<Support>>> declarationMatrix =
            support.list().ofSize(catalog.size() + 1).list().ofSize(languages.size());
        Arbitrary<List<Boolean>> requiredFlags =
            Arbitraries.of(true, false).list().ofSize(catalog.size());
        Arbitrary<Boolean> requireUnknown =
            Arbitraries.frequency(Tuple.of(1, Boolean.TRUE), Tuple.of(4, Boolean.FALSE));
        // Sometimes route the combination through a language with no declaration
        // at all (uppercase, so it can never collide with generated names).
        Arbitrary<Boolean> includeUndeclared =
            Arbitraries.frequency(Tuple.of(1, Boolean.TRUE), Tuple.of(3, Boolean.FALSE));
        Arbitrary<Integer> encryptPick = Arbitraries.integers().between(0, 11);
        Arbitrary<Integer> decryptPick = Arbitraries.integers().between(0, 11);

        return Combinators
            .combine(declarationMatrix, requiredFlags, requireUnknown,
                includeUndeclared, encryptPick, decryptPick)
            .as((matrix, flags, unknownRequired, undeclared, encryptIndex, decryptIndex) -> {
                Map<String, Map<String, Boolean>> declared = new LinkedHashMap<>();
                for (int l = 0; l < languages.size(); l++) {
                    List<Support> row = matrix.get(l);
                    Map<String, Boolean> byFeature = new LinkedHashMap<>();
                    for (int f = 0; f < catalog.size(); f++) {
                        if (row.get(f) != Support.ABSENT) {
                            byFeature.put(catalog.get(f), row.get(f) == Support.SUPPORTED);
                        }
                    }
                    if (row.get(catalog.size()) != Support.ABSENT) {
                        byFeature.put(unknownFeature, row.get(catalog.size()) == Support.SUPPORTED);
                    }
                    if (byFeature.isEmpty()) {
                        // The declarations format requires at least one Feature per
                        // language entry; expectations are computed from this final map.
                        byFeature.put(catalog.get(0), Boolean.TRUE);
                    }
                    declared.put(languages.get(l), byFeature);
                }

                Set<String> required = new LinkedHashSet<>();
                for (int f = 0; f < catalog.size(); f++) {
                    if (flags.get(f)) {
                        required.add(catalog.get(f));
                    }
                }
                if (unknownRequired) {
                    required.add(unknownFeature);
                }
                if (required.isEmpty()) {
                    required.add(catalog.get(0));
                }

                List<String> pool = new ArrayList<>(languages);
                if (undeclared) {
                    pool.add("Undeclared");
                }
                String encrypt = pool.get(encryptIndex % pool.size());
                String decrypt = pool.get(decryptIndex % pool.size());
                return new Scenario(catalog, declared, Set.copyOf(required), encrypt, decrypt);
            });
    }
}
