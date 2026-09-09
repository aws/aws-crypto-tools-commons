package aws.cryptography.testserver.orchestrator.config;

import java.util.List;

/**
 * The {@code Configuration_Set} stored in the Commons_Repository: one
 * {@code product} field, one {@code Feature_Catalog} (the {@code features} list
 * of Feature names), and the collection of {@link ConfigurationEntry}, one per
 * language, with the cross-entry uniqueness invariant on {@code port}.
 *
 * <p>{@code product} and {@code features} are nullable so a Configuration_Set
 * that omits them is representable and rejected by
 * {@link ConfigurationValidation} rather than failing to parse. That structural
 * validation is a pure function that must run before anything is cloned.
 */
public final class ConfigurationSet {

    /** Lowest and highest legal TCP port. */
    public static final int MIN_PORT = 1;
    public static final int MAX_PORT = 65535;

    private final String product;
    private final List<String> features;
    private final List<ConfigurationEntry> entries;
    private final List<String> requiredKmsScenarios;
    private final List<String> bugLedgerIds;

    /** {@link #ConfigurationSet(String, List, List, List)} with no KMS coverage-floor list configured. */
    public ConfigurationSet(String product, List<String> features, List<ConfigurationEntry> entries) {
        this(product, features, entries, null);
    }

    /**
     * The SDK's {@code Configuration_Set} — the shared TestServer runner reads
     * every field from this record.
     *
     * @param product              the product identifier (e.g. {@code "esdk"});
     *                             nullable so a set that omits it is
     *                             representable and rejected by validation
     *                             rather than failing to parse
     * @param features             the Feature_Catalog (or {@code null} when
     *                             absent from the JSON; duplicates are
     *                             preserved for the duplicate-name check)
     * @param entries              one Configuration_Entry per language
     * @param requiredKmsScenarios the SDK's KMS coverage-floor scenarios for
     *                             Requirement 10.4, or {@code null} when the
     *                             SDK does not opt in to a coverage floor
     *                             (empty list equivalent). Each entry is a
     *                             scenario label the Tests' parameterized
     *                             executions include in brackets (e.g.
     *                             {@code blob[awsKms] java-v3->python-v4}).
     */
    public ConfigurationSet(String product, List<String> features,
            List<ConfigurationEntry> entries, List<String> requiredKmsScenarios) {
        this(product, features, entries, requiredKmsScenarios, null);
    }

    /**
     * Full constructor including the commons bug ledger's ids (design "Bug
     * Configuration"): the set of known-bug ids a server's exhibited-bug list
     * may reference. {@code null} when absent (the consolidated
     * configuration-set.json carries no ledger).
     */
    public ConfigurationSet(String product, List<String> features,
            List<ConfigurationEntry> entries, List<String> requiredKmsScenarios,
            List<String> bugLedgerIds) {
        this.product = product;
        // A null Feature_Catalog means "absent from the JSON"; duplicates are
        // preserved for the duplicate-name check.
        this.features = features == null ? null : List.copyOf(features);
        this.entries = List.copyOf(entries);
        this.requiredKmsScenarios = requiredKmsScenarios == null
            ? null : List.copyOf(requiredKmsScenarios);
        this.bugLedgerIds = bugLedgerIds == null ? List.of() : List.copyOf(bugLedgerIds);
    }

    /**
     * Legacy convenience constructor: entries only, no {@code product} and no
     * Feature_Catalog. Retained so existing call sites and tests keep compiling
     * until the resolution rework migrates them.
     */
    public ConfigurationSet(List<ConfigurationEntry> entries) {
        this(null, null, entries);
    }

    /** @return the product identifier (e.g. {@code "esdk"}), or null if absent. */
    public String product() {
        return product;
    }

    /** @return the Feature_Catalog (the {@code features} list), or null if absent. */
    public List<String> features() {
        return features;
    }

    /**
     * @return the SDK's KMS coverage-floor scenarios for Requirement 10.4,
     *     or {@code null} when the SDK did not opt in (equivalent to an
     *     empty list — no floor enforced). Each entry is a scenario label
     *     the Tests' parameterized executions include in brackets.
     */
    public List<String> requiredKmsScenarios() {
        return requiredKmsScenarios;
    }

    public List<ConfigurationEntry> entries() {
        return entries;
    }

    /**
     * @return the commons bug ledger's ids — the known-bug ids a server's
     *     exhibited-bug list may reference (design "Bug Configuration"); empty
     *     when no ledger was configured.
     */
    public List<String> bugLedgerIds() {
        return bugLedgerIds;
    }

    /** @return the entry for {@code language}, or {@code null} if absent. */
    public ConfigurationEntry forLanguage(String language) {
        for (ConfigurationEntry e : entries) {
            if (language.equals(e.language())) {
                return e;
            }
        }
        return null;
    }
}
