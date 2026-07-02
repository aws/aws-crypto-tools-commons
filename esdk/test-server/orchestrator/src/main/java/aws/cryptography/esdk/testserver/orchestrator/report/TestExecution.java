package aws.cryptography.esdk.testserver.orchestrator.report;

/**
 * The outcome of one executed {@code Test} (design Reporter, Property 14). The
 * {@link Outcome#UNREACHABLE} case captures a {@code Language_Server} or backend
 * that could not be reached during the test, which must never be reported as a
 * pass (Requirement 13.3).
 *
 * @param name    the identifying test name (e.g. class#method)
 * @param outcome pass / fail / unreachable
 * @param detail  extra diagnostics (e.g. the unreachable component); may be blank
 */
public record TestExecution(String name, Outcome outcome, String detail) {

    public enum Outcome {
        PASSED,
        FAILED,
        /** The server/backend was unreachable; a special, identified failure. */
        UNREACHABLE
    }

    public static TestExecution passed(String name) {
        return new TestExecution(name, Outcome.PASSED, "");
    }

    public static TestExecution failed(String name, String detail) {
        return new TestExecution(name, Outcome.FAILED, detail == null ? "" : detail);
    }

    public static TestExecution unreachable(String name, String component) {
        return new TestExecution(name, Outcome.UNREACHABLE, component == null ? "" : component);
    }
}
