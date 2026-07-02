package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunner;
import java.net.URI;
import java.util.List;

/**
 * A test double {@link TestRunner}. It either returns a preset list of executions
 * or throws {@link MissingRuntimeConfigException} (to model an absent/incomplete
 * runtime config, Requirement 7.4). It records whether it was invoked so tests
 * can assert that an aborted run executes no Tests (records no partial results).
 */
final class StubTestRunner implements TestRunner {

    private final List<TestExecution> executions;
    private final boolean refuse;
    private boolean invoked = false;

    private StubTestRunner(List<TestExecution> executions, boolean refuse) {
        this.executions = executions;
        this.refuse = refuse;
    }

    static StubTestRunner returning(List<TestExecution> executions) {
        return new StubTestRunner(executions, false);
    }

    /** A runner that refuses to run because no endpoint is configured (Req 7.4). */
    static StubTestRunner refusing() {
        return new StubTestRunner(List.of(), true);
    }

    boolean wasInvoked() {
        return invoked;
    }

    @Override
    public List<TestExecution> run(List<URI> endpoints) throws MissingRuntimeConfigException {
        invoked = true;
        if (refuse) {
            throw new MissingRuntimeConfigException(
                "no target endpoint configured for the Tests; refusing to run (Requirement 7.4)");
        }
        return executions;
    }
}
