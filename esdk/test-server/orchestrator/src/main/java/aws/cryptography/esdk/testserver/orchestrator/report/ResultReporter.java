package aws.cryptography.esdk.testserver.orchestrator.report;

import java.util.ArrayList;
import java.util.List;

/**
 * Produces the fail-open {@link Result} from the set of executed {@code Test}
 * outcomes (design Reporter). This is a <em>pure function</em> over the outcome
 * set (design Testing Strategy — Property 14 runs it in-process), implementing
 * the fail-open rule exactly:
 *
 * <ul>
 *   <li>Success <em>iff</em> at least one Test executed and every executed Test
 *       passed (Requirements 13.1, 11.3).</li>
 *   <li>Any failed Test → failure identifying the failed Test (Requirement 13.2).</li>
 *   <li>Any unreachable server/backend → failure identifying the unreachable
 *       component; that Test is never reported as a pass (Requirement 13.3).</li>
 *   <li>Zero Tests executed → failure (Requirement 13.4).</li>
 * </ul>
 */
public final class ResultReporter {

    /** Report the fail-open result over a set of executed test outcomes. */
    public Result report(List<TestExecution> executions) {
        if (executions == null || executions.isEmpty()) {
            // Zero Tests executed is always a failure (Requirement 13.4).
            return Result.failure(
                "no Tests were executed",
                List.of("zero tests executed (Requirement 13.4)"));
        }

        List<String> unreachable = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        int passed = 0;
        for (TestExecution e : executions) {
            switch (e.outcome()) {
                case PASSED -> passed++;
                case UNREACHABLE -> unreachable.add(
                    e.name() + " -> unreachable: " + e.detail());
                case FAILED -> failed.add(
                    e.name() + " -> failed: " + e.detail());
            }
        }

        // Unreachable is a failure that identifies the component and is never a
        // pass (Requirement 13.3); report it distinctly from ordinary failures.
        if (!unreachable.isEmpty() || !failed.isEmpty()) {
            List<String> details = new ArrayList<>();
            details.addAll(unreachable);
            details.addAll(failed);
            int problems = unreachable.size() + failed.size();
            String summary = problems + " of " + executions.size()
                + " executed Tests did not pass"
                + (unreachable.isEmpty() ? "" : " (" + unreachable.size() + " unreachable)");
            return Result.failure(summary, details);
        }

        return Result.success(
            "all " + passed + " executed Tests passed",
            List.of(passed + " passed"));
    }
}
