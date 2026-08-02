package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import aws.cryptography.esdk.testserver.orchestrator.run.MissingRuntimeConfigException;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunInput;
import aws.cryptography.esdk.testserver.orchestrator.run.TestRunner;
import java.util.List;

/**
 * A test double {@link TestRunner}. It either returns a preset list of executions
 * or throws {@link MissingRuntimeConfigException} (to model an absent/incomplete
 * runtime config). It records whether it was invoked so tests can assert that an
 * aborted run executes no Tests (records no partial results).
 */
final class StubTestRunner implements TestRunner {

    private final List<TestExecution> executions;
    private final boolean refuse;
    private boolean invoked = false;
    private TestRunInput lastInput;

    private StubTestRunner(List<TestExecution> executions, boolean refuse) {
        this.executions = executions;
        this.refuse = refuse;
    }

    static StubTestRunner returning(List<TestExecution> executions) {
        return new StubTestRunner(executions, false);
    }

    /** A runner that refuses to run because no target is configured. */
    static StubTestRunner refusing() {
        return new StubTestRunner(List.of(), true);
    }

    boolean wasInvoked() {
        return invoked;
    }

    /** The input of the most recent {@link #run}, for handoff assertions. */
    TestRunInput lastInput() {
        return lastInput;
    }

    @Override
    public List<TestExecution> run(TestRunInput input) throws MissingRuntimeConfigException {
        invoked = true;
        lastInput = input;
        if (refuse) {
            throw new MissingRuntimeConfigException(
                "no target endpoint configured for the Tests; refusing to run (Requirement 10.2)");
        }
        return executions;
    }
}
