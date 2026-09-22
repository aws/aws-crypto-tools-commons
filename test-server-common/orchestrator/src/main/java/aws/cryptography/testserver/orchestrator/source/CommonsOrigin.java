package aws.cryptography.testserver.orchestrator.source;

import aws.cryptography.testserver.orchestrator.config.RepositoryCoordinates;

/**
 * The coordinates the Commons_Repository was (or will be) cloned at for a
 * Language_Repository_Run, plus why that branch was selected (design
 * "RunContext"): the {@code commons repository entry} branch by default
 * (Requirement 4.5), or the explicit invocation-time branch override in its
 * place (Requirement 4.8).
 *
 * @param url    the Commons_Repository clone URL
 * @param branch the branch selected for the clone
 * @param reason {@link ResolutionReason#CONFIGURATION_ENTRY} when the branch is
 *               the commons repository entry's, or
 *               {@link ResolutionReason#INVOCATION_OVERRIDE} when an explicit
 *               invocation-time override supplied it
 */
public record CommonsOrigin(String url, String branch, ResolutionReason reason) {

    /**
     * Commons-branch selection (Requirements 4.5, 4.8): the invocation override
     * branch wins with reason {@code invocation-override}; otherwise the
     * commons repository entry branch applies with reason
     * {@code configuration-entry}.
     *
     * @param commonsRepository        the commons repository entry
     *                                 coordinates (name, url, branch)
     * @param invocationOverrideBranch the explicit invocation-time branch
     *                                 override, or {@code null}/blank when none
     *                                 was supplied
     */
    public static CommonsOrigin select(
            RepositoryCoordinates commonsRepository, String invocationOverrideBranch) {
        if (invocationOverrideBranch != null && !invocationOverrideBranch.isBlank()) {
            return new CommonsOrigin(
                commonsRepository.url(), invocationOverrideBranch,
                ResolutionReason.INVOCATION_OVERRIDE);
        }
        return new CommonsOrigin(
            commonsRepository.url(), commonsRepository.branch(),
            ResolutionReason.CONFIGURATION_ENTRY);
    }
}
