package aws.cryptography.testserver.orchestrator.config;

import java.util.List;

/**
 * The model of a Language_Repository's per-server configuration — the trio
 * {@code server-config.json} + {@code feature-config.json} + {@code bug-config.json}
 * (e.g. under {@code aws-database-encryption-sdk-dynamodb/test-server/java-v3-server/}). It carries:
 *
 * <ul>
 *   <li>the {@code commons repository entry} ({@code commonsRepository}:
 *       name, url, branch — the clone coordinates for the Commons_Repository,
 *       Requirement 4.4),</li>
 *   <li>the {@code product} field, which must exactly match the
 *       commons configuration's {@code product} (Requirement 8.11),</li>
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
 * @param commonsRepository   the commons repository entry (Requirement 4.4)
 * @param product             the product identifier; must match the
 *                            commons configuration's (Requirement 8.11)
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
public record ServerConfiguration(
    RepositoryCoordinates commonsRepository,
    String product,
    List<String> supportedFeatures,
    List<String> unsupportedFeatures,
    List<String> rawRsaPaddingSchemes,
    List<ConfigurationEntry> configurationOverrides,
    List<String> bugIds
) {
    public ServerConfiguration {
        supportedFeatures = supportedFeatures == null ? null : List.copyOf(supportedFeatures);
        unsupportedFeatures = unsupportedFeatures == null ? null : List.copyOf(unsupportedFeatures);
        rawRsaPaddingSchemes =
            rawRsaPaddingSchemes == null ? null : List.copyOf(rawRsaPaddingSchemes);
        configurationOverrides =
            configurationOverrides == null ? List.of() : List.copyOf(configurationOverrides);
        bugIds = bugIds == null ? List.of() : List.copyOf(bugIds);
    }
}
