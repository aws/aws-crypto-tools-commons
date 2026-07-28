package aws.cryptography.esdk.testserver.orchestrator.source;

import java.nio.file.Path;

/**
 * The execution context of one orchestrated invocation (design "RunContext"):
 * where the run was initiated from, which decides the source-resolution
 * semantics of Requirement 4.
 *
 * <ul>
 *   <li>A {@link Kind#COMMONS} run ({@code Commons_Run}) resolves every
 *       language from the Configuration_Entry values in the commons working
 *       tree (Requirement 4.1). {@code ownLanguage}, {@code languageRepoRoot},
 *       and {@code commonsOrigin} are absent; {@code commonsRoot} is the
 *       commons working tree itself.</li>
 *   <li>A {@link Kind#LANGUAGE} run ({@code Language_Repository_Run}) always
 *       uses the Language_Repository's working tree for its own language
 *       (Requirement 4.2) and resolves every Other language from the commons
 *       clone (Requirement 4.3). {@code commonsRoot} is that clone, and
 *       {@code commonsOrigin} records the coordinates and branch-selection
 *       reason the clone was (or will be) obtained with (Requirements 4.5,
 *       4.8).</li>
 * </ul>
 *
 * @param kind                   the execution context kind
 * @param ownLanguage            the Language_Repository's own language
 *                               (LANGUAGE runs only, else {@code null})
 * @param languageRepoRoot       the Language_Repository working tree root
 *                               (LANGUAGE runs only, else {@code null})
 * @param commonsRoot            the commons checkout the run reads shared
 *                               components from: the working tree (COMMONS) or
 *                               the clone (LANGUAGE)
 * @param invokingRepositoryName canonical name of the repository the invocation
 *                               runs from, matched against Server_Location
 *                               repositories for the working-tree rule
 *                               (Requirement 3.4)
 * @param commonsOrigin          the commons clone coordinates and reason
 *                               (LANGUAGE runs only, else {@code null})
 */
public record RunContext(
    Kind kind,
    String ownLanguage,
    Path languageRepoRoot,
    Path commonsRoot,
    String invokingRepositoryName,
    CommonsOrigin commonsOrigin
) {

    /** The two execution contexts of Requirement 4. */
    public enum Kind { COMMONS, LANGUAGE }

    public RunContext {
        if (kind == null) {
            throw new IllegalArgumentException("kind is required");
        }
        if (commonsRoot == null) {
            throw new IllegalArgumentException("commonsRoot is required");
        }
        if (invokingRepositoryName == null || invokingRepositoryName.isBlank()) {
            throw new IllegalArgumentException("invokingRepositoryName is required");
        }
        if (kind == Kind.COMMONS) {
            if (ownLanguage != null || languageRepoRoot != null || commonsOrigin != null) {
                throw new IllegalArgumentException(
                    "a Commons_Run carries no ownLanguage, languageRepoRoot, or commonsOrigin");
            }
        } else {
            if (ownLanguage == null || ownLanguage.isBlank()) {
                throw new IllegalArgumentException(
                    "a Language_Repository_Run requires an ownLanguage");
            }
            if (languageRepoRoot == null) {
                throw new IllegalArgumentException(
                    "a Language_Repository_Run requires a languageRepoRoot");
            }
            if (commonsOrigin == null) {
                throw new IllegalArgumentException(
                    "a Language_Repository_Run requires a commonsOrigin");
            }
        }
    }

    /** A {@code Commons_Run} from the commons working tree at {@code commonsRoot}. */
    public static RunContext commonsRun(Path commonsRoot, String invokingRepositoryName) {
        return new RunContext(Kind.COMMONS, null, null, commonsRoot,
            invokingRepositoryName, null);
    }

    /** A {@code Language_Repository_Run} from {@code languageRepoRoot} for {@code ownLanguage}. */
    public static RunContext languageRun(
            String ownLanguage,
            Path languageRepoRoot,
            Path commonsRoot,
            String invokingRepositoryName,
            CommonsOrigin commonsOrigin) {
        return new RunContext(Kind.LANGUAGE, ownLanguage, languageRepoRoot, commonsRoot,
            invokingRepositoryName, commonsOrigin);
    }

    /**
     * The working tree of the repository the invocation runs from — the root a
     * Server_Location naming {@link #invokingRepositoryName} resolves under
     * (Requirement 3.4).
     */
    public Path invokingWorkingTreeRoot() {
        return kind == Kind.COMMONS ? commonsRoot : languageRepoRoot;
    }
}
