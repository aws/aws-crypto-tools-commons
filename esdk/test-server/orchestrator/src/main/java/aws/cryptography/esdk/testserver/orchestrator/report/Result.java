package aws.cryptography.esdk.testserver.orchestrator.report;

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
}
