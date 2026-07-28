package aws.cryptography.esdk.testserver.orchestrator.report;

/**
 * The outcome of one {@code Test} × Target-combination JUnit test case. The
 * {@link Outcome#UNREACHABLE} case captures a {@code Language_Server} or backend
 * that could not be reached during the test, which must never be reported as a
 * pass (Requirement 10.7). The {@link Outcome#SKIPPED} case captures a
 * Feature-gated (or otherwise aborted) test case, carrying the JUnit XML
 * {@code <skipped message>} so skips are reported distinctly from passes and
 * failures (Requirement 9.6) and excluded from the executed set
 * (Requirement 2.8).
 *
 * <p>Exactly one outcome exists per test × combination because each combination
 * is one JUnit test case (Requirements 9.8–9.10).
 *
 * @param name    the identifying test name (e.g. class#method)
 * @param outcome pass / fail / unreachable / skipped
 * @param detail  extra diagnostics (e.g. the unreachable component, or the skip
 *                message); may be blank
 */
public record TestExecution(String name, Outcome outcome, String detail) {

    public enum Outcome {
        PASSED,
        FAILED,
        /** The server/backend was unreachable; a special, identified failure. */
        UNREACHABLE,
        /** The test case was skipped (e.g. a Feature-gated skip); not executed. */
        SKIPPED
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

    /** A skipped test case carrying the JUnit XML {@code <skipped message>} (Req 9.6). */
    public static TestExecution skipped(String name, String message) {
        return new TestExecution(name, Outcome.SKIPPED, message == null ? "" : message);
    }
}
