package aws.cryptography.testserver.orchestrator.config;

/**
 * The {@code Server_Location} of a {@code Configuration_Entry}: the coordinates
 * locating a language's Language_Server implementation — the hosting repository,
 * the reference (branch) to obtain it at, and the path within that repository
 * (Requirement 3.1).
 *
 * <p>Fields are deliberately nullable so a {@code serverLocation} object with a
 * missing element parsed from JSON is representable and rejected by validation
 * (task 1.2) with an error naming the language and each missing element, raised
 * before anything is cloned (Requirement 3.8).
 *
 * @param repository canonical name of the hosting repository (matched against
 *                   the invoking repository for the working-tree rule, Req 3.4)
 * @param url        clone URL of the hosting repository
 * @param ref        the reference (branch) to obtain the repository at
 * @param path       the server directory relative to the repository root
 */
public record ServerLocation(String repository, String url, String ref, String path) {
}
