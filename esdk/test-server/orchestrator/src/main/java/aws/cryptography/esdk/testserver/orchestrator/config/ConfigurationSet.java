package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.List;

/**
 * The {@code Configuration_Set} stored in the Commons_Repository: exactly one
 * {@code product} field identifying the product, exactly one
 * {@code Feature_Catalog} (the {@code features} list of Feature names,
 * Requirement 7.1), and the collection of {@link ConfigurationEntry}, one per
 * language, with the cross-entry uniqueness invariant on {@code port}
 * (Requirement 3.2).
 *
 * <p>{@code product} and {@code features} are nullable so a Configuration_Set
 * that omits them is representable and rejected by
 * {@link ConfigurationValidation} (Requirement 7.4) rather than failing to
 * parse. Structural validation lives in {@link ConfigurationValidation}, a pure
 * function that must run before anything is cloned.
 */
public final class ConfigurationSet {

    /** Lowest and highest legal TCP port (Requirement 3.2). */
    public static final int MIN_PORT = 1;
    public static final int MAX_PORT = 65535;

    private final String product;
    private final List<String> features;
    private final List<ConfigurationEntry> entries;

    public ConfigurationSet(String product, List<String> features, List<ConfigurationEntry> entries) {
        this.product = product;
        // A null Feature_Catalog means "absent from the JSON" (rejected by
        // validation, Requirement 7.4); duplicates are preserved for the
        // duplicate-name check (Requirement 7.5).
        this.features = features == null ? null : List.copyOf(features);
        this.entries = List.copyOf(entries);
    }

    /**
     * Legacy convenience constructor: entries only, no {@code product} and no
     * Feature_Catalog. Retained so existing call sites and tests keep compiling
     * until the resolution rework (task 2.1) migrates them.
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

    public List<ConfigurationEntry> entries() {
        return entries;
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
