package aws.cryptography.esdk.testserver.orchestrator.config;

/**
 * One entry in the {@link ConfigurationSet}, describing a single
 * {@code Language_Server}'s branch, repository, major version, and port
 * (Requirement 9.1, 9.2, design "Configuration_Entry").
 *
 * <p>Fields are deliberately nullable so an under-specified entry parsed from
 * {@code configuration-set.json} (a missing field) is representable and can be
 * rejected by {@link ConfigurationSet#validate()} with an error that identifies
 * the offending entry, rather than failing to parse.
 *
 * @param language     logical key, e.g. {@code "java"}; matches a Language_Server
 * @param branch       non-empty branch identifier (Requirement 9.2)
 * @param repository   non-empty repository identifier (Requirement 9.2)
 * @param majorVersion integer &gt;= 1 (Requirement 9.2)
 * @param port         integer in 1..65535, unique across the set (Req 9.2, 9.3)
 */
public record ConfigurationEntry(
    String language,
    String branch,
    String repository,
    Integer majorVersion,
    Integer port
) {
    /** Human-readable identity used in validation errors (never throws). */
    public String identity() {
        return (language == null || language.isBlank()) ? "<unnamed entry>" : language;
    }
}
