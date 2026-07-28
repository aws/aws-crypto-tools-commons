package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.List;

/**
 * One entry in the {@link ConfigurationSet}, describing a single language: its
 * {@code Library_Repository}, major version, port, and {@code Server_Location}
 * (Requirements 3.1, 3.2, design "Configuration_Entry"); for a language with no
 * Language_Repository (Python), the entry also carries that language's
 * {@code Feature_Declaration} — the {@code supportedFeatures} and
 * {@code unsupportedFeatures} arrays (Requirements 8.1, 8.3).
 *
 * <p>Fields are deliberately nullable so an under-specified entry parsed from
 * {@code configuration-set.json} (a missing field or object) is representable
 * and can be rejected by validation with an error that identifies the offending
 * entry and each missing element, rather than failing to parse. A {@code null}
 * feature array means the array was absent from the JSON — distinct from an
 * empty array, which is a present, empty declaration half.
 *
 * @param language            logical key, e.g. {@code "java"}; unique in the set
 * @param majorVersion        integer &gt;= 1 (Requirement 3.2)
 * @param port                integer in 1..65535, unique across the set (Req 3.2)
 * @param libraryRepository   coordinates of the language's ESDK library source
 *                            (Requirement 3.2)
 * @param serverLocation      coordinates of the language's Language_Server
 *                            implementation (Requirement 3.1)
 * @param supportedFeatures   the Feature_Declaration's supported half, or
 *                            {@code null} when absent (Requirements 8.1, 8.3)
 * @param unsupportedFeatures the Feature_Declaration's unsupported half, or
 *                            {@code null} when absent (Requirements 8.1, 8.3)
 */
public record ConfigurationEntry(
    String language,
    Integer majorVersion,
    Integer port,
    RepositoryCoordinates libraryRepository,
    ServerLocation serverLocation,
    List<String> supportedFeatures,
    List<String> unsupportedFeatures
) {
    public ConfigurationEntry {
        // Defensive copies; null is preserved to mean "absent from the JSON".
        supportedFeatures = supportedFeatures == null ? null : List.copyOf(supportedFeatures);
        unsupportedFeatures = unsupportedFeatures == null ? null : List.copyOf(unsupportedFeatures);
    }

    /**
     * Legacy convenience constructor for the pre-factoring flat
     * {@code (language, branch, repository, majorVersion, port)} shape. The flat
     * {@code branch}/{@code repository} pair maps onto the
     * {@code libraryRepository} object; no Server_Location or
     * Feature_Declaration is carried. Retained so existing call sites and tests
     * keep compiling until the validation rework (task 1.2) migrates them.
     */
    public ConfigurationEntry(String language, String branch, String repository,
            Integer majorVersion, Integer port) {
        this(language, majorVersion, port,
            new RepositoryCoordinates(repository, null, branch, RepositoryCoordinates.DEFAULT_PATH),
            null, null, null);
    }

    /** Legacy accessor: the library branch, from {@code libraryRepository}. */
    public String branch() {
        return libraryRepository == null ? null : libraryRepository.branch();
    }

    /** Legacy accessor: the library repository name, from {@code libraryRepository}. */
    public String repository() {
        return libraryRepository == null ? null : libraryRepository.name();
    }

    /** @return true iff the entry carries a Feature_Declaration (either array present). */
    public boolean hasFeatureDeclaration() {
        return supportedFeatures != null || unsupportedFeatures != null;
    }

    /** Human-readable identity used in validation errors (never throws). */
    public String identity() {
        return (language == null || language.isBlank()) ? "<unnamed entry>" : language;
    }
}
