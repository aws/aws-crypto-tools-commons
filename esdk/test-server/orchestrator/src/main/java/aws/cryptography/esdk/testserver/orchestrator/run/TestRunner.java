package aws.cryptography.esdk.testserver.orchestrator.run;

import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import java.net.URI;
import java.util.List;

/**
 * Runs the single Java {@code Tests} suite against launched endpoints, pointing it
 * there through runtime configuration only (Requirements 7.2, 7.3). Implementations
 * must refuse to run — throwing {@link MissingRuntimeConfigException} and recording
 * no partial results — when no endpoint is configured (Requirement 7.4).
 *
 * <p>Kept as an interface so the orchestrator's gating and reporting can be
 * exercised without launching a real Gradle test run.
 */
public interface TestRunner {

    /**
     * Run the Tests against {@code endpoints} (first = encrypt, second = decrypt;
     * a single entry is used for both sides).
     *
     * @return one {@link TestExecution} per executed Test
     * @throws MissingRuntimeConfigException if {@code endpoints} is empty (Req 7.4)
     */
    List<TestExecution> run(List<URI> endpoints) throws MissingRuntimeConfigException;
}
