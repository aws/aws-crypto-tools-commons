package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.List;

/**
 * The model of a Language_Repository's commons-configuration file (e.g.
 * {@code aws-crypto-tools-java/esdk/test-server/commons-configuration.json}). It
 * carries the {@code Commons_Configuration_Entry} clone coordinates, the
 * {@code product} field (must match the Configuration_Set's), the language's
 * {@code Feature_Declaration}, and optional {@code configurationOverrides} that
 * each fully replace the commons-stored entry for another language.
 *
 * <p>Fields are deliberately nullable so an under-specified file is
 * representable and rejected by validation naming each missing element, rather
 * than failing to parse. A {@code null} feature array means the array was absent
 * from the JSON; {@code configurationOverrides} defaults to an empty list.
 *
 * @param configurationOverrides complete replacement Configuration_Entries for
 *                            Other languages; never null
 */
public record CommonsConfiguration(
    RepositoryCoordinates commonsRepository,
    String product,
    List<String> supportedFeatures,
    List<String> unsupportedFeatures,
    List<ConfigurationEntry> configurationOverrides
) {
    public CommonsConfiguration {
        supportedFeatures = supportedFeatures == null ? null : List.copyOf(supportedFeatures);
        unsupportedFeatures = unsupportedFeatures == null ? null : List.copyOf(unsupportedFeatures);
        configurationOverrides =
            configurationOverrides == null ? List.of() : List.copyOf(configurationOverrides);
    }
}
