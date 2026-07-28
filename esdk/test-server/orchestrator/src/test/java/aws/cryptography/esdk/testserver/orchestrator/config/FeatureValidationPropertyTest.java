package aws.cryptography.esdk.testserver.orchestrator.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for Feature validation (design Property 2): catalog
 * duplicate-name validation ({@link ConfigurationValidation}) and per-language
 * Feature_Declaration + product-match validation ({@link FeatureValidation}).
 *
 * <p>The generator produces a Feature_Catalog, a product pair, a language, and
 * a valid partition of the catalog into {@code supportedFeatures} /
 * {@code unsupportedFeatures}, then applies exactly one targeted mutation (or
 * none). Validation must succeed if and only if no mutation was applied, and
 * every failure must name the language and each affected Feature — or, for a
 * product mismatch, the Language_Repository and both product values.
 *
 * <p>Everything under test is pure — no I/O, no git, no servers.
 *
 * <p><b>Validates: Requirements 7.2, 7.5, 8.5, 8.6, 8.7, 8.8, 8.9, 8.11</b>
 */
class FeatureValidationPropertyTest {

    /** Catalog names are drawn from this pool (kept disjoint from UNKNOWN_NAME). */
    private static final List<String> FEATURE_POOL =
        List.of("streaming", "MPL", "compression", "caching", "signing", "vectors");

    /** A Feature name guaranteed never to be in a generated catalog. */
    private static final String UNKNOWN_NAME = "uncataloged-feature";

    private static final List<String> PRODUCT_POOL = List.of("esdk", "dbesdk", "s3ec");

    private static final List<String> LANGUAGE_POOL = List.of("java", "python", "rust", "go");

    /** The single targeted mutation applied to an otherwise-valid scenario. */
    private enum Mutation {
        NONE,               // valid partition, matching product → must validate
        UNDECLARED,         // drop a catalog Feature from its array (Req 8.6)
        CONFLICT,           // put a catalog Feature in both arrays (Req 8.7)
        UNKNOWN,            // add a non-catalog name to an array (Req 8.8)
        DUPLICATE,          // repeat a name within its array (Req 8.9)
        PRODUCT_MISMATCH,   // commons-configuration product differs (Req 8.11)
        CATALOG_DUPLICATE   // duplicate a name in the catalog itself (Req 7.5)
    }

    /**
     * One generated case: the (duplicate-free) catalog, the catalog as handed
     * to catalog validation (possibly containing a duplicated name), the
     * declaration arrays after mutation, the product pair, and which Feature
     * (if any) the mutation touched.
     */
    private record Scenario(
        List<String> catalog,
        List<String> catalogForValidation,
        String product,
        String fileProduct,
        String language,
        String languageRepository,
        List<String> supported,
        List<String> unsupported,
        Mutation mutation,
        String affectedFeature,
        String affectedArray) {
    }

    // Feature: test-server-factoring, Property 2: Feature validation accepts exactly the catalog-complete declarations
    @Property(tries = 300)
    void featureValidationAcceptsExactlyTheCatalogCompleteDeclarations(
            @ForAll("scenarios") Scenario s) {

        // --- Catalog validation (Requirements 7.2, 7.5): fails naming each
        // duplicated name exactly when two or more Features share a name.
        ConfigurationSetValidation catalogValidation = ConfigurationValidation.validate(
            new ConfigurationSet(s.product(), s.catalogForValidation(),
                List.of(validEntry(s.language()))));
        if (s.mutation() == Mutation.CATALOG_DUPLICATE) {
            assertFalse(catalogValidation.valid(),
                "a catalog with a duplicated Feature name must fail validation: "
                    + s.catalogForValidation());
            assertTrue(catalogValidation.message().contains(
                    "duplicate Feature name '" + s.affectedFeature() + "'"),
                "the catalog error must name the duplicated Feature "
                    + s.affectedFeature() + ": " + catalogValidation.errors());
        } else {
            assertTrue(catalogValidation.valid(),
                "a duplicate-free catalog must pass catalog validation, but got: "
                    + catalogValidation.errors());
        }

        // --- Per-language validation (Requirements 8.5–8.9, 8.11), always
        // against the duplicate-free catalog: succeeds iff every catalog
        // Feature is in exactly one array, no unknown names, no in-array
        // duplicates, and the products match exactly.
        FeatureValidation.Result result = FeatureValidation
            .validateDeclaration(s.catalog(), s.language(), s.supported(), s.unsupported())
            .and(FeatureValidation.validateProductMatch(
                s.languageRepository(), s.fileProduct(), s.product()));

        switch (s.mutation()) {
            case NONE, CATALOG_DUPLICATE -> assertTrue(result.valid(),
                "a catalog-complete declaration with a matching product must"
                    + " validate, but got: " + result.errors());
            case UNDECLARED -> {
                assertFalse(result.valid(),
                    "a catalog Feature in neither array must fail validation");
                assertTrue(anyError(result, e -> e.contains("language " + s.language())
                        && e.contains(quoted(s.affectedFeature()))
                        && e.contains("undeclared")),
                    "the undeclared error must name the language and Feature "
                        + s.affectedFeature() + ": " + result.errors());
            }
            case CONFLICT -> {
                assertFalse(result.valid(),
                    "a catalog Feature in both arrays must fail validation");
                assertTrue(anyError(result, e -> e.contains("language " + s.language())
                        && e.contains(quoted(s.affectedFeature()))
                        && e.contains("both")),
                    "the conflict error must name the language and Feature "
                        + s.affectedFeature() + ": " + result.errors());
            }
            case UNKNOWN -> {
                assertFalse(result.valid(),
                    "a Feature outside the catalog must fail validation");
                assertTrue(anyError(result, e -> e.contains("language " + s.language())
                        && e.contains(quoted(s.affectedFeature()))
                        && e.contains("unknown")
                        && e.contains(s.affectedArray())),
                    "the unknown-Feature error must name the language, the Feature "
                        + s.affectedFeature() + ", and the array "
                        + s.affectedArray() + ": " + result.errors());
            }
            case DUPLICATE -> {
                assertFalse(result.valid(),
                    "a Feature repeated within an array must fail validation");
                assertTrue(anyError(result, e -> e.contains("language " + s.language())
                        && e.contains(quoted(s.affectedFeature()))
                        && e.contains(s.affectedArray())),
                    "the duplicate error must name the language, the Feature "
                        + s.affectedFeature() + ", and the array "
                        + s.affectedArray() + ": " + result.errors());
            }
            case PRODUCT_MISMATCH -> {
                assertFalse(result.valid(),
                    "a commons-configuration product differing from the"
                        + " Configuration_Set product must fail validation");
                assertTrue(anyError(result, e -> e.contains(s.languageRepository())
                        && e.contains(quoted(s.fileProduct()))
                        && e.contains(quoted(s.product()))),
                    "the product-mismatch error must name the Language_Repository"
                        + " and both product values: " + result.errors());
            }
            default -> throw new IllegalStateException("unhandled " + s.mutation());
        }
    }

    // ------------------------------------------------------------------
    // Generators
    // ------------------------------------------------------------------

    @Provide
    Arbitrary<Scenario> scenarios() {
        Arbitrary<List<String>> catalogs =
            Arbitraries.subsetOf(FEATURE_POOL).ofMinSize(1).map(ArrayList::new);
        return catalogs.flatMap(catalog -> Combinators.combine(
                Arbitraries.of(Boolean.TRUE, Boolean.FALSE).list().ofSize(catalog.size()),
                Arbitraries.of(PRODUCT_POOL),
                Arbitraries.of(LANGUAGE_POOL),
                Arbitraries.of(Mutation.values()),
                Arbitraries.integers().between(0, 9999))
            .as((assignment, product, language, mutation, seed) ->
                buildScenario(catalog, assignment, product, language, mutation, seed)));
    }

    /**
     * Build a valid partition of {@code catalog} into the two arrays (feature i
     * goes to supportedFeatures iff {@code assignment.get(i)}), then apply
     * exactly one targeted mutation. {@code seed} picks the mutated Feature.
     */
    private static Scenario buildScenario(
            List<String> catalog, List<Boolean> assignment, String product,
            String language, Mutation mutation, int seed) {
        List<String> supported = new ArrayList<>();
        List<String> unsupported = new ArrayList<>();
        for (int i = 0; i < catalog.size(); i++) {
            (assignment.get(i) ? supported : unsupported).add(catalog.get(i));
        }

        int targetIndex = Math.floorMod(seed, catalog.size());
        String target = catalog.get(targetIndex);
        boolean targetSupported = assignment.get(targetIndex);
        List<String> targetArray = targetSupported ? supported : unsupported;
        String targetArrayName = targetSupported ? "supportedFeatures" : "unsupportedFeatures";

        List<String> catalogForValidation = new ArrayList<>(catalog);
        String fileProduct = product;
        String affectedFeature = null;
        String affectedArray = null;

        switch (mutation) {
            case NONE -> { }
            case UNDECLARED -> {
                targetArray.remove(target);
                affectedFeature = target;
            }
            case CONFLICT -> {
                (targetSupported ? unsupported : supported).add(target);
                affectedFeature = target;
            }
            case UNKNOWN -> {
                boolean intoSupported = seed % 2 == 0;
                (intoSupported ? supported : unsupported).add(UNKNOWN_NAME);
                affectedFeature = UNKNOWN_NAME;
                affectedArray = intoSupported ? "supportedFeatures" : "unsupportedFeatures";
            }
            case DUPLICATE -> {
                targetArray.add(target);
                affectedFeature = target;
                affectedArray = targetArrayName;
            }
            case PRODUCT_MISMATCH -> fileProduct = product + "-mismatched";
            case CATALOG_DUPLICATE -> {
                catalogForValidation.add(target);
                affectedFeature = target;
            }
            default -> throw new IllegalStateException("unhandled " + mutation);
        }

        return new Scenario(catalog, catalogForValidation, product, fileProduct,
            language, "aws-crypto-tools-" + language, supported, unsupported,
            mutation, affectedFeature, affectedArray);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** A structurally complete entry so catalog validation sees no other errors. */
    private static ConfigurationEntry validEntry(String language) {
        return new ConfigurationEntry(language, 3, 8091,
            new RepositoryCoordinates("repo-" + language,
                "git@github.com:aws/repo-" + language + ".git", "main", "."),
            new ServerLocation("aws-crypto-tools-commons",
                "git@github.com:aws/aws-crypto-tools-commons.git", "main",
                "esdk/test-server/servers/" + language),
            null, null);
    }

    private static boolean anyError(
            FeatureValidation.Result result,
            java.util.function.Predicate<String> predicate) {
        return result.errors().stream().anyMatch(predicate);
    }

    /** Mirror {@link FeatureValidation}'s quoting of Feature/product values. */
    private static String quoted(String value) {
        return "\"" + value + "\"";
    }
}
