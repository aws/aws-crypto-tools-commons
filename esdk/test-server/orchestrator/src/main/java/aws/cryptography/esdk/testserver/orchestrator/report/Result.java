package aws.cryptography.esdk.testserver.orchestrator.report;

import java.util.ArrayList;
import java.util.List;

/**
 * The single fail-open conformance outcome of an orchestrator run — the
 * {@code Result<Boolean>} of the closure (design Overview, Requirement 13). A
 * broken, unreachable, or never-run set of {@code Tests} is always a failure,
 * never a pass.
 *
 * @param succeeded {@code true} iff at least one Test executed and all passed
 * @param summary   a one-line human-readable outcome
 * @param details   supporting diagnostics (failed tests, unreachable components,
 *                  or the abort cause)
 */
public record Result(boolean succeeded, String summary, List<String> details) {

    public Result {
        details = List.copyOf(details);
    }

    public static Result success(String summary, List<String> details) {
        return new Result(true, summary, details);
    }

    public static Result failure(String summary, List<String> details) {
        return new Result(false, summary, details);
    }

    /** A failure that aborts before any Test runs (invalid config, conflicts, etc.). */
    public static Result abort(String cause) {
        return new Result(false, "run aborted: " + cause, List.of(cause));
    }

    /**
     * This result with teardown cleanup failures appended, naming each language
     * whose {@code Language_Server} was still running (Requirement 2.11). The
     * primary result is never masked: {@code succeeded} and the original
     * summary/details are preserved, with the cleanup information appended —
     * the abort-path counterpart of the reporter's cleanup handling.
     *
     * @param cleanupFailureLanguages each affected language; empty returns
     *     {@code this} unchanged
     */
    public Result withCleanupFailures(List<String> cleanupFailureLanguages) {
        if (cleanupFailureLanguages == null || cleanupFailureLanguages.isEmpty()) {
            return this;
        }
        List<String> appended = new ArrayList<>(details);
        for (String language : cleanupFailureLanguages) {
            appended.add("cleanup failure: the " + language
                + " Language_Server was not stopped (still running) (Requirement 2.11)");
        }
        return new Result(succeeded,
            summary + "; cleanup failure: Language_Server(s) still running for "
                + String.join(", ", cleanupFailureLanguages),
            appended);
    }
}
