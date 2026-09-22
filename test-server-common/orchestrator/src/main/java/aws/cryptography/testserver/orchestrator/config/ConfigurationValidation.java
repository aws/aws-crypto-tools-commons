package aws.cryptography.testserver.orchestrator.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure structural validation of the run's configuration: the
 * {@link CommonsConfiguration} together with any Configuration_Overrides supplied by
 * the invoking Language_Repository.
 *
 * <p>Everything here is a pure function over the already-parsed models — no
 * I/O, no git — so the pipeline can (and must) run it <em>before anything is
 * cloned</em>. The checks:
 *
 * <ul>
 *   <li><b>Catalog level</b>: a non-empty {@code product}, a present
 *       Feature_Catalog ({@code features}), and no Feature name duplicated
 *       within the catalog under exact string comparison.</li>
 *   <li><b>Per entry</b>: a non-empty language, a {@code majorVersion >= 1}, a
 *       port in {@value CommonsConfiguration#MIN_PORT}..{@value CommonsConfiguration#MAX_PORT},
 *       a complete {@code libraryRepository} (name, url, branch), and a complete
 *       {@code serverLocation} (repository, ref, path) — every error names the
 *       language and each missing element.</li>
 *   <li><b>Overrides</b>: each Configuration_Override is validated structurally
 *       exactly like a commons-stored entry; an override naming the run's own
 *       language is rejected (the own language resolves to its working tree), as
 *       is an override naming a language with no commons-stored entry.</li>
 *   <li><b>Effective set</b>: port uniqueness is checked across the
 *       <em>effective</em> set — the commons-stored entries with each overridden
 *       language's entry replaced by its override.</li>
 * </ul>
 *
 * <p>Feature_Declaration content validation is {@code FeatureValidation}'s job,
 * not this class's.
 */
public final class ConfigurationValidation {

    private ConfigurationValidation() {
    }

    /**
     * Validate a commons configuration with no overrides and no own language — the
     * Commons_Run shape.
     */
    public static CommonsConfigurationValidation validate(CommonsConfiguration set) {
        return validate(set, List.of(), null);
    }

    /**
     * Validate the run's structural configuration.
     *
     * @param set         the commons-stored commons configuration
     * @param overrides   the invoking Language_Repository's
     *                    Configuration_Overrides (empty for a Commons_Run)
     * @param ownLanguage the run's own language for a Language_Repository_Run,
     *                    or {@code null} for a Commons_Run
     * @return the validation outcome; {@code valid()} is {@code false} with one
     *     message per problem, each naming the offending language and element
     */
    public static CommonsConfigurationValidation validate(
            CommonsConfiguration set, List<ConfigurationEntry> overrides, String ownLanguage) {
        List<String> errors = new ArrayList<>();

        validateCatalog(set, errors);

        for (ConfigurationEntry entry : set.entries()) {
            validateEntry("entry", entry, errors);
        }

        Set<String> commonsLanguages = new HashSet<>();
        for (ConfigurationEntry entry : set.entries()) {
            if (entry.language() != null && !entry.language().isBlank()) {
                commonsLanguages.add(entry.language());
            }
        }

        // Overrides are validated structurally exactly like commons entries,
        // then checked against the override sanity rules.
        Map<String, ConfigurationEntry> applicableOverrides = new LinkedHashMap<>();
        for (ConfigurationEntry override : overrides) {
            validateEntry("override", override, errors);
            String language = override.language();
            if (language == null || language.isBlank()) {
                continue; // already reported as missing language above
            }
            if (language.equals(ownLanguage)) {
                // The own language resolves to its working tree.
                errors.add("override " + language + ": a Configuration_Override must not name"
                    + " the run's own language '" + language
                    + "' — the own language resolves to its working tree");
                continue;
            }
            if (!commonsLanguages.contains(language)) {
                errors.add("override " + language + ": no commons-stored Configuration_Entry"
                    + " exists for language '" + language + "'");
                continue;
            }
            applicableOverrides.put(language, override);
        }

        validatePortUniqueness(effectiveEntries(set, applicableOverrides), errors);

        return new CommonsConfigurationValidation(errors.isEmpty(), errors);
    }

    /**
     * Validate the run's reference implementation — the language whose
     * Language_Server plays the immaterial side of single-sided Tests — against
     * the commons configuration's languages. Pure, so the pipeline runs it before
     * anything is cloned; an invalid value aborts naming it and listing the
     * configured languages.
     */
    public static CommonsConfigurationValidation validateReferenceImplementation(
            CommonsConfiguration set, String referenceImplementation) {
        List<String> languages = new ArrayList<>();
        for (ConfigurationEntry entry : set.entries()) {
            if (entry.language() != null && !entry.language().isBlank()) {
                languages.add(entry.language());
            }
        }
        if (referenceImplementation == null || referenceImplementation.isBlank()) {
            return new CommonsConfigurationValidation(false, List.of(
                "missing value (configured languages: " + languages + ")"));
        }
        if (!languages.contains(referenceImplementation)) {
            return new CommonsConfigurationValidation(false, List.of(
                "'" + referenceImplementation + "' is not a configured language"
                    + " (configured languages: " + languages + ")"));
        }
        return new CommonsConfigurationValidation(true, List.of());
    }

    // ------------------------------------------------------------------
    // Catalog level
    // ------------------------------------------------------------------

    private static void validateCatalog(CommonsConfiguration set, List<String> errors) {
        if (set.product() == null || set.product().isBlank()) {
            errors.add("commons configuration: missing product");
        }
        List<String> features = set.features();
        if (features == null) {
            errors.add("commons configuration: missing Feature_Catalog (features)");
            return;
        }
        // Duplicate Feature names under exact string comparison, naming each
        // duplicated name once.
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String name : features) {
            counts.merge(name, 1, Integer::sum);
        }
        for (Map.Entry<String, Integer> count : counts.entrySet()) {
            if (count.getValue() > 1) {
                errors.add("Feature_Catalog: duplicate Feature name '"
                    + count.getKey() + "'");
            }
        }
    }

    // ------------------------------------------------------------------
    // Per-entry structure
    // ------------------------------------------------------------------

    private static void validateEntry(String kind, ConfigurationEntry e, List<String> errors) {
        String id = kind + " " + e.identity();

        if (e.language() == null || e.language().isBlank()) {
            errors.add(id + ": missing language");
        }
        if (e.majorVersion() == null) {
            errors.add(id + ": missing majorVersion");
        } else if (e.majorVersion() < 1) {
            errors.add(id + ": majorVersion " + e.majorVersion() + " must be >= 1");
        }
        if (e.port() == null) {
            errors.add(id + ": missing port");
        } else if (e.port() < CommonsConfiguration.MIN_PORT || e.port() > CommonsConfiguration.MAX_PORT) {
            errors.add(id + ": port " + e.port() + " out of range "
                + CommonsConfiguration.MIN_PORT + ".." + CommonsConfiguration.MAX_PORT);
        }

        RepositoryCoordinates library = e.libraryRepository();
        if (library == null) {
            errors.add(id + ": missing libraryRepository");
        } else {
            if (library.name() == null || library.name().isBlank()) {
                errors.add(id + ": libraryRepository missing name");
            }
            if (library.url() == null || library.url().isBlank()) {
                errors.add(id + ": libraryRepository missing url");
            }
            if (library.branch() == null || library.branch().isBlank()) {
                errors.add(id + ": libraryRepository missing branch");
            }
        }

        ServerLocation location = e.serverLocation();
        if (location == null) {
            errors.add(id + ": missing serverLocation");
        } else {
            if (location.repository() == null || location.repository().isBlank()) {
                errors.add(id + ": serverLocation missing repository");
            }
            if (location.ref() == null || location.ref().isBlank()) {
                errors.add(id + ": serverLocation missing ref");
            }
            if (location.path() == null || location.path().isBlank()) {
                errors.add(id + ": serverLocation missing path");
            }
        }
    }

    // ------------------------------------------------------------------
    // Effective set and port uniqueness
    // ------------------------------------------------------------------

    /**
     * The run-effective entries: the commons-stored entries with each
     * overridden language's entry replaced by its Configuration_Override.
     */
    private static List<ConfigurationEntry> effectiveEntries(
            CommonsConfiguration set, Map<String, ConfigurationEntry> applicableOverrides) {
        List<ConfigurationEntry> effective = new ArrayList<>();
        for (ConfigurationEntry entry : set.entries()) {
            ConfigurationEntry override = entry.language() == null
                ? null
                : applicableOverrides.get(entry.language());
            effective.add(override == null ? entry : override);
        }
        return effective;
    }

    private static void validatePortUniqueness(
            List<ConfigurationEntry> effective, List<String> errors) {
        // Only well-formed ports participate; a missing/out-of-range port has
        // already been reported per entry.
        Map<Integer, String> portOwner = new HashMap<>();
        for (ConfigurationEntry e : effective) {
            Integer port = e.port();
            if (port == null || port < CommonsConfiguration.MIN_PORT
                    || port > CommonsConfiguration.MAX_PORT) {
                continue;
            }
            String prior = portOwner.putIfAbsent(port, e.identity());
            if (prior != null) {
                errors.add("entries " + prior + " and " + e.identity()
                    + " share port " + port);
            }
        }
    }
}
