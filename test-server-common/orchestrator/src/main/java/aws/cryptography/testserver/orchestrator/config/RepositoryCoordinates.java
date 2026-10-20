package aws.cryptography.testserver.orchestrator.config;

/**
 * Coordinates of a git repository holding a component's source (design "Data
 * Models"): the {@code libraryRepository} object of a {@code Configuration_Entry}
 * (Requirement 3.2) and the {@code commonsRepository} object (the
 * {@code commons repository entry}, Requirement 4.4) of a
 * Language_Repository's commons-configuration file.
 *
 * <p>Fields are deliberately nullable so an under-specified object parsed from
 * JSON is representable and rejected by validation (task 1.2) with an error that
 * names the language and each missing element, rather than failing to parse.
 *
 * @param name   canonical repository name, e.g. {@code "aws-database-encryption-sdk-dynamodb"}
 * @param url    clone URL
 * @param branch branch to obtain the repository at
 * @param path   path within the repository (defaults to {@link #DEFAULT_PATH}
 *               when omitted in JSON)
 */
public record RepositoryCoordinates(String name, String url, String branch, String path) {

    /** The design default for an omitted {@code path}: the repository root. */
    public static final String DEFAULT_PATH = ".";
}
