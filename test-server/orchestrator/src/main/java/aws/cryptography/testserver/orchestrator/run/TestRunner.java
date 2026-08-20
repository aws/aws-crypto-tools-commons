package aws.cryptography.testserver.orchestrator.run;

import aws.cryptography.testserver.orchestrator.report.TestExecution;
import java.util.List;

/**
 * Runs the single Java {@code Tests} suite against the launched Targets,
 * pointing it there through runtime configuration only (Requirement 10.2): the
 * {@code testserver.targets}, {@code testserver.features}, and
 * {@code testserver.featureCatalog} properties carried by the
 * {@link TestRunInput}. Implementations must refuse to run — throwing
 * {@link MissingRuntimeConfigException} and recording no partial results — when
 * no Target is configured.
 *
 * <p>Kept as an interface so the orchestrator's gating and reporting can be
 * exercised without launching a real Gradle test run.
 */
public interface TestRunner {

    /**
     * Run the Tests over the Cross_Language_Matrix of {@code input.targets()}
     * (Requirement 2.2), gated by the flattened Feature_Declarations.
     *
     * @return one {@link TestExecution} per Tests JUnit test case — exactly one
     *     status (passed / failed / unreachable / skipped) each (Req 9.10)
     * @throws MissingRuntimeConfigException if {@code input} carries no Target
     */
    List<TestExecution> run(TestRunInput input) throws MissingRuntimeConfigException;
}
