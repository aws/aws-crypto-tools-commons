package aws.cryptography.testserver.orchestrator.config;

import java.util.List;

/**
 * The model of a Language_Repository's commons-configuration file (e.g.
 * {@code aws-crypto-tools-java/esdk/test-server/commons-configuration.json},
 * design "Commons-configuration file"). It carries:
 *
 * <ul>
 *   <li>the {@code Commons_Configuration_Entry} ({@code commonsRepository}:
 *       name, url, branch — the clone coordinates for the Commons_Repository,
 *       Requirement 4.4),</li>
 *   <li>the {@code product} field, which must exactly match the
 *       Configuration_Set's {@code product} (Requirement 8.11),</li>
 *   <li>the repository language's {@code Feature_Declaration} — the
 *       {@code supportedFeatures} / {@code unsupportedFeatures} arrays
 *       (Requirements 8.1, 8.2) and the optional {@code rawRsaPaddingSchemes}
 *       capability (the raw-RSA padding schemes the library supports; absent
 *       means all),</li>
 *   <li>optional {@code configurationOverrides}: each a <em>complete</em>
 *       {@link ConfigurationEntry} replacing the commons-stored entry for that
 *       language (Requirement 4.6).</li>
 * </ul>
 *
 * <p>Fields are deliberately nullable so an under-specified file is
 * representable and rejected by validation naming each missing element, rather
 * than failing to parse. A {@code null} feature array means the array was absent
 * from the JSON; {@code configurationOverrides} defaults to an empty list.
 *
 * @param commonsRepository   the Commons_Configuration_Entry (Requirement 4.4)
 * @param product             the product identifier; must match the
 *                            Configuration_Set's (Requirement 8.11)
 * @param supportedFeatures   the Feature_Declaration's supported half, or
 *                            {@code null} when absent
 * @param unsupportedFeatures the Feature_Declaration's unsupported half, or
 *                            {@code null} when absent
 * @param rawRsaPaddingSchemes the raw-RSA padding schemes the language's library
 *                            supports, or {@code null} when absent — absent means
 *                            every scheme the Smithy model defines (see
 *                            {@link FeatureValidation#validateRawRsaPaddingSchemes})
 * @param configurationOverrides complete replacement Configuration_Entries for
 *                            Other languages; never null
 */
public record CommonsConfiguration(
    RepositoryCoordinates commonsRepository,
    String product,
    List<String> supportedFeatures,
    List<String> unsupportedFeatures,
    List<String> rawRsaPaddingSchemes,
    List<ConfigurationEntry> configurationOverrides,
    List<String> bugIds
) {
    public CommonsConfiguration {
        supportedFeatures = supportedFeatures == null ? null : List.copyOf(supportedFeatures);
        unsupportedFeatures = unsupportedFeatures == null ? null : List.copyOf(unsupportedFeatures);
        rawRsaPaddingSchemes =
            rawRsaPaddingSchemes == null ? null : List.copyOf(rawRsaPaddingSchemes);
        configurationOverrides =
            configurationOverrides == null ? List.of() : List.copyOf(configurationOverrides);
        bugIds = bugIds == null ? List.of() : List.copyOf(bugIds);
    }

    /**
     * Backward-compatible constructor for a commons-configuration with no
     * exhibited-bug list (the consolidated commons-configuration.json carries
     * none). Preserves the pre-bug-config 6-arg shape so existing call sites
     * keep compiling.
     */
    public CommonsConfiguration(
            RepositoryCoordinates commonsRepository, String product,
            List<String> supportedFeatures, List<String> unsupportedFeatures,
            List<String> rawRsaPaddingSchemes, List<ConfigurationEntry> configurationOverrides) {
        this(commonsRepository, product, supportedFeatures, unsupportedFeatures,
            rawRsaPaddingSchemes, configurationOverrides, null);
    }
}
