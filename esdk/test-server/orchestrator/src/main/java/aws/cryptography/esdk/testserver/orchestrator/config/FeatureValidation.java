package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure Feature_Declaration validation (design "FeatureValidation" and
 * "Feature_Declaration validation rules (both carriers)").
 *
 * <p>A Feature_Declaration is the pair of {@code supportedFeatures} and
 * {@code unsupportedFeatures} arrays, wherever it lives: a language with no
 * Language_Repository (Python) carries it in its {@link ConfigurationEntry};
 * a language with one (Java) carries it in that repository's
 * commons-configuration file ({@link CommonsConfiguration}). The rules are
 * identical for both carriers, so this class takes the raw pieces — the
 * Feature_Catalog, the language name, and the two arrays — and no I/O ever
 * happens here.
 *
 * <p>The rules, validated against the run's Feature_Catalog for every
 * participating language before any Test (Requirement 8.4):
 *
 * <ul>
 *   <li>Every catalog Feature must appear in <b>exactly one</b> of the two
 *       arrays: appearing in neither is an undeclared-Feature error
 *       (Requirement 8.6); appearing in both is a conflict error
 *       (Requirement 8.7).</li>
 *   <li>A Feature named in either array that the catalog does not define is
 *       an unknown-Feature error (Requirement 8.8).</li>
 *   <li>A Feature name repeated within either array, under exact string
 *       comparison, is a duplicate error naming each duplicated name
 *       (Requirement 8.9).</li>
 *   <li>The {@code product} in a commons-configuration file must exactly
 *       match the Configuration_Set's {@code product}; a missing or
 *       mismatched value names the Language_Repository and both values
 *       (Requirement 8.11).</li>
 *   <li>A missing or unparseable carrying file is an error naming the
 *       language and the expected Feature_Declaration location
 *       (Requirement 8.10).</li>
 * </ul>
 *
 * <p>Every error names the language (or, for the product check, the
 * Language_Repository) and each affected Feature (or both product values).
 * A {@code null} array means the array was absent from the JSON (see
 * {@link ConfigurationLoader}); no Feature can appear in an absent array, so
 * with both arrays absent every catalog Feature is reported undeclared.
 */
public final class FeatureValidation {

    /**
     * The raw-RSA padding schemes the Smithy model defines (the
     * {@code PaddingScheme} enum in {@code model/esdk-test-server.smithy});
     * {@code PaddingSchemeCatalogTest} pins this list against the model. A
     * declaration's {@code rawRsaPaddingSchemes} names must come from here.
     */
    public static final List<String> RAW_RSA_PADDING_SCHEMES = List.of(
        "PKCS1",
        "OAEP_SHA1_MGF1",
        "OAEP_SHA256_MGF1",
        "OAEP_SHA384_MGF1",
        "OAEP_SHA512_MGF1");

    /**
     * The outcome of a Feature validation check. When {@link #valid()} is
     * {@code false}, {@link #errors()} lists one message per problem, each
     * naming the language (or Language_Repository) and each affected Feature
     * (or both product values), so the run halts before any Test executes.
     *
     * @param valid  {@code true} iff no rule was violated
     * @param errors the problems found (empty iff {@code valid})
     */
    public record Result(boolean valid, List<String> errors) {

        public Result {
            errors = List.copyOf(errors);
        }

        /** A valid result with no errors. */
        public static Result ok() {
            return new Result(true, List.of());
        }

        /** A result carrying {@code errors}; valid iff the list is empty. */
        public static Result of(List<String> errors) {
            return new Result(errors.isEmpty(), errors);
        }

        /** Combine two results: valid iff both are, errors concatenated in order. */
        public Result and(Result other) {
            if (valid && other.valid) {
                return this;
            }
            List<String> combined = new ArrayList<>(errors);
            combined.addAll(other.errors);
            return new Result(false, combined);
        }

        /** @return a single joined error message (for aborting a run). */
        public String message() {
            return String.join("; ", errors);
        }
    }

    private FeatureValidation() {
    }

    /**
     * Validate one Language_Server's {@code bug-configuration.json} list
     * structurally (the known-bug analogue of {@link #validateDeclaration}): no
     * blank ids and no duplicates. There is no central catalogue of bug ids, so
     * membership is not checked — the list is authoritative for that server; a
     * gate on an id no server declares simply asserts live everywhere.
     *
     * @param language  the language whose bug list this is; named in every error
     * @param knownBugs the parsed bug ids, or {@code null} when the server ships
     *                  no bug-configuration file (declares no bug)
     * @return a {@link Result} with one error per structural violation
     */
    public static Result validateKnownBugs(String language, List<String> knownBugs) {
        if (knownBugs == null) {
            return Result.ok();
        }
        List<String> errors = new ArrayList<>();
        addBlankErrors(errors, language, "bug-configuration", knownBugs);
        addDuplicateErrors(errors, language, "known bug", "bug-configuration", knownBugs);
        return Result.of(errors);
    }

    /**
     * Validate one participating language's Feature_Declaration against the
     * Feature_Catalog (Requirements 8.5–8.9).
     *
     * @param featureCatalog      the Configuration_Set's {@code features} list
     *                            (catalog-level presence/duplicate checks are
     *                            Requirements 7.4/7.5, validated elsewhere;
     *                            duplicates here are tolerated by de-duplication)
     * @param language            the language whose declaration this is; named
     *                            in every error
     * @param supportedFeatures   the declaration's supported half, or
     *                            {@code null} when absent from the JSON
     * @param unsupportedFeatures the declaration's unsupported half, or
     *                            {@code null} when absent from the JSON
     * @return a {@link Result} with one error per violated (rule, Feature) pair
     */
    public static Result validateDeclaration(
            List<String> featureCatalog,
            String language,
            List<String> supportedFeatures,
            List<String> unsupportedFeatures) {
        List<String> errors = new ArrayList<>();

        List<String> supported = supportedFeatures == null ? List.of() : supportedFeatures;
        List<String> unsupported = unsupportedFeatures == null ? List.of() : unsupportedFeatures;
        Set<String> catalog = featureCatalog == null
            ? new LinkedHashSet<>() : new LinkedHashSet<>(featureCatalog);

        // In-array duplicates, exact string comparison (Requirement 8.9):
        // each duplicated name is named once per array it is duplicated in.
        addDuplicateErrors(errors, language, "Feature", "supportedFeatures", supported);
        addDuplicateErrors(errors, language, "Feature", "unsupportedFeatures", unsupported);

        // Unknown Features in either array (Requirement 8.8): each unknown
        // name is named once per array it appears in.
        addUnknownErrors(errors, language, "supportedFeatures", supported, catalog);
        addUnknownErrors(errors, language, "unsupportedFeatures", unsupported, catalog);

        Set<String> supportedSet = new HashSet<>(supported);
        Set<String> unsupportedSet = new HashSet<>(unsupported);

        // Both-arrays conflicts (Requirement 8.7): any name, catalog-defined
        // or not, present in both arrays.
        Set<String> union = new LinkedHashSet<>(supported);
        union.addAll(unsupported);
        for (String name : union) {
            if (supportedSet.contains(name) && unsupportedSet.contains(name)) {
                errors.add("language " + language + ": Feature " + quote(name)
                    + " appears in both supportedFeatures and unsupportedFeatures");
            }
        }

        // Catalog coverage (Requirements 8.5, 8.6): every catalog Feature in
        // at least one array; "exactly one" is completed by the conflict rule.
        for (String feature : catalog) {
            if (!supportedSet.contains(feature) && !unsupportedSet.contains(feature)) {
                errors.add("language " + language + ": Feature " + quote(feature)
                    + " is undeclared: it appears in neither supportedFeatures"
                    + " nor unsupportedFeatures");
            }
        }

        return Result.of(errors);
    }

    /**
     * Validate one language's optional {@code rawRsaPaddingSchemes} capability —
     * the raw-RSA padding schemes its library supports, carried next to the
     * Feature_Declaration in either carrier. An <b>absent</b> field ({@code null})
     * is valid and means every scheme in {@link #RAW_RSA_PADDING_SCHEMES}; a
     * present field means exactly that subset. Rules for a present field:
     *
     * <ul>
     *   <li>every name must be a scheme the Smithy model defines
     *       ({@link #RAW_RSA_PADDING_SCHEMES}) — an unknown name is an error,</li>
     *   <li>an empty list is an error: a language with no usable raw-RSA padding
     *       declares the {@code raw-rsa} Feature unsupported instead,</li>
     *   <li>a name repeated within the list, under exact string comparison, is
     *       an error,</li>
     *   <li>the field is only meaningful for a language that declares the
     *       {@code raw-rsa} Feature supported — present with {@code raw-rsa}
     *       absent from {@code supportedFeatures} is an error.</li>
     * </ul>
     *
     * @param language          the language whose capability this is; named in
     *                          every error
     * @param paddingSchemes    the declared schemes, or {@code null} when the
     *                          field was absent from the JSON
     * @param supportedFeatures the same declaration's supported half, or
     *                          {@code null} when absent
     * @return a {@link Result} with one error per violated (rule, name) pair
     */
    public static Result validateRawRsaPaddingSchemes(
            String language,
            List<String> paddingSchemes,
            List<String> supportedFeatures) {
        if (paddingSchemes == null) {
            return Result.ok();
        }
        List<String> errors = new ArrayList<>();

        if (paddingSchemes.isEmpty()) {
            errors.add("language " + language + ": rawRsaPaddingSchemes is empty:"
                + " a language with no usable raw-RSA padding declares the"
                + " raw-rsa Feature unsupported instead");
        }

        addDuplicateErrors(errors, language, "raw-RSA padding scheme",
            "rawRsaPaddingSchemes", paddingSchemes);

        for (String name : new LinkedHashSet<>(paddingSchemes)) {
            if (!RAW_RSA_PADDING_SCHEMES.contains(name)) {
                errors.add("language " + language + ": unknown raw-RSA padding scheme "
                    + quote(name) + " in rawRsaPaddingSchemes: the model defines "
                    + RAW_RSA_PADDING_SCHEMES);
            }
        }

        List<String> supported = supportedFeatures == null ? List.of() : supportedFeatures;
        if (!supported.contains("raw-rsa")) {
            errors.add("language " + language + ": rawRsaPaddingSchemes is declared"
                + " but Feature \"raw-rsa\" is not in supportedFeatures");
        }

        return Result.of(errors);
    }

    /**
     * Validate the {@code product} of a Language_Repository's
     * commons-configuration file against the Configuration_Set's
     * {@code product}, under exact string comparison (Requirement 8.11).
     *
     * @param languageRepository          the Language_Repository whose
     *                                    commons-configuration file this is;
     *                                    named in the error
     * @param commonsConfigurationProduct the file's {@code product}, or
     *                                    {@code null} when missing
     * @param configurationSetProduct     the Configuration_Set's {@code product}
     * @return a valid {@link Result}, or one error naming the
     *     Language_Repository and both product values
     */
    public static Result validateProductMatch(
            String languageRepository,
            String commonsConfigurationProduct,
            String configurationSetProduct) {
        if (commonsConfigurationProduct == null) {
            return Result.of(List.of(
                "Language_Repository " + languageRepository
                    + ": commons-configuration product is missing;"
                    + " the Configuration_Set product is "
                    + quote(configurationSetProduct)));
        }
        if (!Objects.equals(commonsConfigurationProduct, configurationSetProduct)) {
            return Result.of(List.of(
                "Language_Repository " + languageRepository
                    + ": commons-configuration product "
                    + quote(commonsConfigurationProduct)
                    + " does not match the Configuration_Set product "
                    + quote(configurationSetProduct)));
        }
        return Result.ok();
    }

    /**
     * The error for a missing or unparseable file carrying a participating
     * language's Feature_Declaration, naming the language and the expected
     * Feature_Declaration location (Requirement 8.10). The caller supplies the
     * load-failure cause (e.g. a {@link ConfigurationLoadException} message).
     *
     * @param language         the language whose declaration could not be read
     * @param expectedLocation the expected location of the carrying file
     * @param cause            the load-failure cause, or {@code null}
     * @return an invalid {@link Result} with exactly one error
     */
    public static Result carryingFileError(
            String language, String expectedLocation, String cause) {
        return Result.of(List.of(
            "language " + language
                + ": the file carrying its Feature_Declaration is missing or"
                + " unparseable; expected location: " + expectedLocation
                + (cause == null || cause.isBlank() ? "" : " (" + cause + ")")));
    }

    // ------------------------------------------------------------------
    // Rule helpers (pure)
    // ------------------------------------------------------------------

    /** Requirement 8.9: name each value repeated within {@code array}. */
    private static void addDuplicateErrors(
            List<String> errors, String language, String noun,
            String arrayName, List<String> array) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String name : array) {
            counts.merge(name, 1, Integer::sum);
        }
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (e.getValue() > 1) {
                errors.add("language " + language + ": " + noun + " " + quote(e.getKey())
                    + " appears " + e.getValue() + " times in " + arrayName);
            }
        }
    }

    /** Requirement 8.8: name each Feature in {@code array} the catalog does not define. */
    private static void addUnknownErrors(
            List<String> errors, String language, String arrayName,
            List<String> array, Set<String> catalog) {
        Set<String> seen = new LinkedHashSet<>(array);
        for (String name : seen) {
            if (!catalog.contains(name)) {
                errors.add("language " + language + ": unknown Feature " + quote(name)
                    + " in " + arrayName
                    + ": the Feature_Catalog does not define it");
            }
        }
    }

    /** Name each null or blank entry in {@code array} (position-based, since it has no name). */
    private static void addBlankErrors(
            List<String> errors, String language, String arrayName, List<String> array) {
        for (int i = 0; i < array.size(); i++) {
            String value = array.get(i);
            if (value == null || value.isBlank()) {
                errors.add("language " + language + ": " + arrayName + " has a blank entry at index " + i);
            }
        }
    }

    /** Quote a Feature or product value for an error message ({@code null} → "null"). */
    private static String quote(String value) {
        return value == null ? "null" : "\"" + value + "\"";
    }
}
