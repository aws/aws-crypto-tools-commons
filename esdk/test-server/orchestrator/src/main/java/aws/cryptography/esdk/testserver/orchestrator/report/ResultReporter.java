package aws.cryptography.esdk.testserver.orchestrator.report;

import java.util.ArrayList;
import java.util.List;

/**
 * Produces the fail-open {@link Result} from the executed {@code Test} outcomes,
 * the launched Target set, and the teardown close results (design
 * "ResultReporter"). This is a <em>pure function</em> over its inputs,
 * implementing the fail-open rule exactly:
 *
 * <ul>
 *   <li><strong>Executed</strong> = {@code PASSED | FAILED | UNREACHABLE};
 *       {@code SKIPPED} test cases never count as executed
 *       (Requirement 2.8).</li>
 *   <li>Success <em>iff</em> at least one Test executed, every executed Test
 *       passed, and the KMS coverage floor holds; zero executed Tests or any
 *       failed execution ⇒ the run failed (Requirements 2.8, 2.10).</li>
 *   <li>Any failed Test → failure identifying the failed Test and, through the
 *       Tests' stable {@code …[<scenario>…] <encrypt>-><decrypt>} naming, the
 *       (encrypt, decrypt) Target combination it failed on
 *       (Requirement 10.5).</li>
 *   <li>Any {@code UNREACHABLE} execution → failure identifying the
 *       unreachable {@code Language_Server} and the Test that was executing;
 *       it is never reported as a pass (Requirement 10.7).</li>
 *   <li><strong>KMS coverage floor</strong>: for every launched
 *       (encrypt, decrypt) Target pair — the full pairwise product of the
 *       launched Target labels, same-Target pairs included — and each required
 *       KMS scenario in {@link #REQUIRED_KMS_SCENARIOS}, at least one passed
 *       execution must match the naming convention; each hole fails the run
 *       naming the scenario and the pair (Requirement 10.4).</li>
 *   <li>Cleanup failures (a {@code Language_Server} still running after
 *       teardown) are appended to the report naming each affected language,
 *       without masking the primary run result (Requirement 2.11).</li>
 * </ul>
 */
public final class ResultReporter {

    /**
     * The required KMS scenario labels — a documented constant mirroring the
     * Tests module's {@code EsdkClientConfigs} KMS scenario labels exactly
     * (Requirement 10.4). The Tests name each execution
     * {@code …[<scenario>…] <encrypt>-><decrypt>} (e.g.
     * {@code blob[awsKms] java-v3->python-v4}); if the Tests rename a scenario
     * the floor fails loudly, which is the fail-open behavior Requirement 10
     * exists to guarantee — silent coverage loss is exactly what it prevents.
     */
    public static final List<String> REQUIRED_KMS_SCENARIOS = List.of(
        "awsKms",
        "awsKmsMrk",
        "awsKmsMultiKeyring",
        "awsKmsMrkMultiKeyring",
        "awsKmsRsa",
        "awsKmsDiscovery");

    /**
     * Report over the executed outcomes alone: no launched Targets are known
     * (the KMS coverage floor is vacuously satisfied) and no close results are
     * available. Orchestrated runs use
     * {@link #report(List, List, List)} — the floor is always on for them.
     */
    public Result report(List<TestExecution> executions) {
        return report(executions, List.of(), List.of());
    }

    /**
     * Report the fail-open result of an orchestrated run.
     *
     * @param executions the parsed test-case outcomes (skips included; they are
     *     excluded from the executed set here, Requirement 2.8)
     * @param launchedTargetLabels the labels of every launched Target,
     *     {@code <language>-v<majorVersion>} (e.g. {@code java-v3}) — the KMS
     *     coverage floor spans their full pairwise (encrypt, decrypt) product,
     *     same-Target pairs included (Requirement 10.4)
     * @param cleanupFailureLanguages each language whose {@code Language_Server}
     *     was still running after teardown (a {@code STILL_RUNNING} close
     *     result, Requirement 2.11)
     */
    public Result report(
            List<TestExecution> executions,
            List<String> launchedTargetLabels,
            List<String> cleanupFailureLanguages) {
        List<TestExecution> all = executions == null ? List.of() : executions;
        List<String> targets = launchedTargetLabels == null ? List.of() : launchedTargetLabels;
        List<String> cleanupFailures =
            cleanupFailureLanguages == null ? List.of() : cleanupFailureLanguages;

        // Partition the outcomes. Skipped test cases are reported distinctly and
        // never count as executed (Requirement 2.8).
        int passed = 0;
        int skipped = 0;
        List<String> unreachable = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        for (TestExecution e : all) {
            switch (e.outcome()) {
                case PASSED -> passed++;
                case SKIPPED -> skipped++;
                // The unreachable Language_Server (the detail) and the Test that
                // was executing are both identified (Requirement 10.7).
                case UNREACHABLE -> unreachable.add(
                    e.name() + " -> unreachable Language_Server: " + e.detail());
                // The test name embeds the (encrypt, decrypt) combination via the
                // Tests' `…[<scenario>…] <encrypt>-><decrypt>` naming (Req 10.5).
                case FAILED -> failed.add(
                    e.name() + " -> failed: " + e.detail());
            }
        }
        int executed = passed + unreachable.size() + failed.size();

        // KMS coverage floor (Requirement 10.4): every launched (encrypt, decrypt)
        // pair × every required KMS scenario needs at least one PASSED execution.
        List<String> kmsHoles = kmsCoverageHoles(all, targets);

        boolean succeeded = executed > 0
            && unreachable.isEmpty()
            && failed.isEmpty()
            && kmsHoles.isEmpty();

        List<String> details = new ArrayList<>();
        String summary;
        if (executed == 0) {
            // Zero executed Tests is always a failure (Requirements 2.8, 2.10);
            // a skip-only run executes nothing.
            summary = "no Tests were executed";
            details.add("zero tests executed"
                + (skipped > 0 ? " (" + skipped + " skipped; skips are not executions)" : "")
                + " (Requirement 2.10)");
            details.addAll(kmsHoles);
        } else if (!succeeded) {
            details.addAll(unreachable);
            details.addAll(failed);
            details.addAll(kmsHoles);
            int problems = unreachable.size() + failed.size();
            StringBuilder sb = new StringBuilder();
            if (problems > 0) {
                sb.append(problems).append(" of ").append(executed)
                    .append(" executed Tests did not pass");
                if (!unreachable.isEmpty()) {
                    sb.append(" (").append(unreachable.size()).append(" unreachable)");
                }
            }
            if (!kmsHoles.isEmpty()) {
                if (sb.length() > 0) {
                    sb.append("; ");
                }
                sb.append(kmsHoles.size())
                    .append(" KMS coverage floor hole(s) (Requirement 10.4)");
            }
            summary = sb.toString();
        } else {
            summary = "all " + executed + " executed Tests passed";
            details.add(passed + " passed"
                + (skipped > 0 ? ", " + skipped + " skipped (not executed)" : ""));
        }

        // Cleanup failures are appended, naming each affected language, without
        // masking the primary result (Requirement 2.11).
        if (!cleanupFailures.isEmpty()) {
            for (String language : cleanupFailures) {
                details.add("cleanup failure: the " + language
                    + " Language_Server was not stopped (still running) (Requirement 2.11)");
            }
            summary += "; cleanup failure: Language_Server(s) still running for "
                + String.join(", ", cleanupFailures);
        }

        return new Result(succeeded, summary, details);
    }

    /**
     * Compute the KMS coverage floor holes: for every ordered (encrypt, decrypt)
     * pair of launched Target labels (same-Target pairs included) and every
     * required KMS scenario, at least one {@code PASSED} execution must match the
     * Tests' {@code …[<scenario>…] <encrypt>-><decrypt>} naming. Only passed
     * executions satisfy the floor — a failed or unreachable KMS execution is
     * already a failure of its own and does not provide coverage.
     *
     * @return one detail line per hole, naming the scenario and the pair.
     */
    private static List<String> kmsCoverageHoles(
            List<TestExecution> executions, List<String> launchedTargetLabels) {
        List<String> holes = new ArrayList<>();
        List<String> passedNames = executions.stream()
            .filter(e -> e.outcome() == TestExecution.Outcome.PASSED)
            .map(TestExecution::name)
            .toList();
        for (String encrypt : launchedTargetLabels) {
            for (String decrypt : launchedTargetLabels) {
                String pair = encrypt + "->" + decrypt;
                for (String scenario : REQUIRED_KMS_SCENARIOS) {
                    boolean covered = passedNames.stream().anyMatch(
                        name -> mentionsScenario(name, scenario) && mentionsPair(name, pair));
                    if (!covered) {
                        holes.add("KMS coverage floor hole: scenario " + scenario
                            + " has no passed execution for combination " + pair
                            + " (Requirement 10.4)");
                    }
                }
            }
        }
        return holes;
    }

    /**
     * Whether {@code name} names the {@code scenario} per the Tests' bracket
     * convention: it contains {@code [<scenario>} at a label boundary — the
     * character after the label, if any, is not a label character — so
     * {@code awsKms} never matches {@code [awsKmsMrk]}.
     */
    private static boolean mentionsScenario(String name, String scenario) {
        String needle = "[" + scenario;
        int idx = name.indexOf(needle);
        while (idx >= 0) {
            int after = idx + needle.length();
            if (after >= name.length() || !isLabelChar(name.charAt(after))) {
                return true;
            }
            idx = name.indexOf(needle, idx + 1);
        }
        return false;
    }

    /**
     * Whether {@code name} contains the {@code <encrypt>-><decrypt>} pair string
     * at label boundaries on both sides, so one Target label never matches
     * inside a longer label.
     */
    private static boolean mentionsPair(String name, String pair) {
        int idx = name.indexOf(pair);
        while (idx >= 0) {
            boolean startOk = idx == 0 || !isLabelChar(name.charAt(idx - 1));
            int after = idx + pair.length();
            boolean endOk = after >= name.length() || !isLabelChar(name.charAt(after));
            if (startOk && endOk) {
                return true;
            }
            idx = name.indexOf(pair, idx + 1);
        }
        return false;
    }

    /** Characters that can appear inside a Target label or scenario label. */
    private static boolean isLabelChar(char c) {
        return Character.isLetterOrDigit(c) || c == '-' || c == '.' || c == '_';
    }
}
