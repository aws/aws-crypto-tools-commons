package aws.cryptography.esdk.testserver.orchestrator.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the reworked {@link ResultReporter}: the executed set excludes
 * skips (Requirement 2.8), success iff ≥1 executed and 0 failed/unreachable
 * (Requirement 2.10), failure details identify the Test and its
 * (encrypt, decrypt) combination (Requirements 10.5, 10.7), the KMS coverage
 * floor gates success over the launched pairwise product (Requirement 10.4),
 * and cleanup failures are appended naming each language without masking the
 * primary result (Requirement 2.11).
 */
class ResultReporterTest {

    private final ResultReporter reporter = new ResultReporter();

    private static final List<String> NO_TARGETS = List.of();
    private static final List<String> NO_CLEANUP = List.of();

    // -------------------------------------------------------------------
    // Executed set and the fail-open rule (Requirements 2.8, 2.10).
    // -------------------------------------------------------------------

    @Test
    void allPassedIsSuccess() {
        Result result = reporter.report(List.of(
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->java-v3"),
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->python-v4")),
            NO_TARGETS, NO_CLEANUP);
        assertTrue(result.succeeded(), () -> "expected success: " + result);
    }

    @Test
    void zeroExecutionsIsFailure() {
        Result result = reporter.report(List.of(), NO_TARGETS, NO_CLEANUP);
        assertFalse(result.succeeded());
        assertTrue(result.summary().toLowerCase().contains("no tests"),
            () -> "empty run must report zero tests executed: " + result.summary());
    }

    @Test
    void skippedOnlyIsZeroExecutedAndFails() {
        // Skips are excluded from the executed set (Requirement 2.8): a run of
        // nothing but Feature-gated skips executed zero Tests (Requirement 2.10).
        Result result = reporter.report(List.of(
                TestExecution.skipped("Tests#stream[rawAes+default] java-v3->python-v4",
                    "feature-gated skip: feature=streaming unsupported by [python]"),
                TestExecution.skipped("Tests#stream[rawAes+default] python-v4->python-v4",
                    "feature-gated skip: feature=streaming unsupported by [python]")),
            NO_TARGETS, NO_CLEANUP);
        assertFalse(result.succeeded());
        assertTrue(result.summary().toLowerCase().contains("no tests"),
            () -> "skip-only run must count as zero executed: " + result.summary());
    }

    @Test
    void skipsAlongsidePassesDoNotAffectSuccess() {
        Result result = reporter.report(List.of(
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->java-v3"),
                TestExecution.skipped("Tests#stream[rawAes+default] java-v3->python-v4",
                    "feature-gated skip")),
            NO_TARGETS, NO_CLEANUP);
        assertTrue(result.succeeded(), () -> "skips must not fail a passing run: " + result);
    }

    @Test
    void failedExecutionFailsTheRunIdentifyingTestAndCombination() {
        // The test name embeds the (encrypt, decrypt) combination via the Tests'
        // `…[<scenario>…] <encrypt>-><decrypt>` naming (Requirement 10.5).
        String name = "Tests#blob[rawRsa+default] java-v3->python-v4";
        Result result = reporter.report(List.of(
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->java-v3"),
                TestExecution.failed(name, "assertion failed")),
            NO_TARGETS, NO_CLEANUP);
        assertFalse(result.succeeded());
        assertTrue(result.details().stream().anyMatch(d -> d.contains(name)),
            () -> "failure must identify the failed Test and combination: " + result.details());
        assertTrue(result.details().stream().anyMatch(d -> d.contains("java-v3->python-v4")),
            () -> "failure detail must carry the (encrypt, decrypt) combination: "
                + result.details());
    }

    @Test
    void unreachableFailsTheRunNamingServerAndTest() {
        // An unreachable Language_Server is never a pass; the report identifies
        // both the unresponsive server and the executing Test (Requirement 10.7).
        String name = "Tests#blob[awsKms] python-v4->java-v3";
        Result result = reporter.report(List.of(
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->java-v3"),
                TestExecution.unreachable(name,
                    "ConnectException: Connection refused to python-v4 at 127.0.0.1:8092")),
            NO_TARGETS, NO_CLEANUP);
        assertFalse(result.succeeded());
        assertTrue(result.details().stream().anyMatch(
                d -> d.contains(name) && d.contains("unreachable")
                    && d.contains("python-v4 at 127.0.0.1:8092")),
            () -> "unreachable detail must name the Test and the Language_Server: "
                + result.details());
    }

    // -------------------------------------------------------------------
    // KMS coverage floor (Requirement 10.4).
    // -------------------------------------------------------------------

    @Test
    void requiredKmsScenariosMirrorEsdkClientConfigs() {
        // The documented constant mirrors the Tests module's EsdkClientConfigs
        // KMS scenario labels exactly (Requirement 10.4).
        assertEquals(
            List.of("awsKms", "awsKmsMrk", "awsKmsMultiKeyring", "awsKmsRsa", "awsKmsDiscovery"),
            ResultReporter.REQUIRED_KMS_SCENARIOS);
    }

    @Test
    void fullKmsCoverageOverAllLaunchedPairsSucceeds() {
        List<String> targets = List.of("java-v3", "python-v4");
        Result result = reporter.report(
            fullKmsCoverage(targets), targets, NO_CLEANUP);
        assertTrue(result.succeeded(), () -> "full KMS coverage must pass: " + result);
    }

    @Test
    void aSingleKmsHoleFailsNamingScenarioAndPair() {
        List<String> targets = List.of("java-v3", "python-v4");
        List<TestExecution> executions = new ArrayList<>(fullKmsCoverage(targets));
        // Remove exactly the awsKmsRsa python-v4->java-v3 coverage.
        executions.removeIf(e ->
            e.name().contains("[awsKmsRsa]") && e.name().contains("python-v4->java-v3"));

        Result result = reporter.report(executions, targets, NO_CLEANUP);
        assertFalse(result.succeeded(), "a KMS coverage hole must fail the run");
        assertTrue(result.details().stream().anyMatch(
                d -> d.contains("awsKmsRsa") && d.contains("python-v4->java-v3")),
            () -> "the hole must name the scenario and the pair: " + result.details());
    }

    @Test
    void floorSpansSameTargetPairs() {
        // The pairwise product includes same-target pairs: with one launched
        // target, the floor still requires all five scenarios on target->target.
        List<String> targets = List.of("java-v3");
        Result missingSamePair = reporter.report(List.of(
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->java-v3")),
            targets, NO_CLEANUP);
        assertFalse(missingSamePair.succeeded());
        assertTrue(missingSamePair.details().stream().anyMatch(
                d -> d.contains("awsKms") && d.contains("java-v3->java-v3")),
            () -> "same-target holes must be reported: " + missingSamePair.details());

        Result covered = reporter.report(fullKmsCoverage(targets), targets, NO_CLEANUP);
        assertTrue(covered.succeeded(), () -> "covered same-target pair must pass: " + covered);
    }

    @Test
    void aScenarioLabelPrefixDoesNotSatisfyTheFloor() {
        // awsKmsMrk coverage must not satisfy the awsKms requirement even though
        // "awsKms" is a prefix of "awsKmsMrk" (label-boundary matching).
        List<String> targets = List.of("java-v3");
        List<TestExecution> executions = new ArrayList<>(fullKmsCoverage(targets));
        executions.removeIf(e -> e.name().contains("[awsKms]"));

        Result result = reporter.report(executions, targets, NO_CLEANUP);
        assertFalse(result.succeeded(),
            "awsKmsMrk executions must not satisfy the awsKms scenario requirement");
        assertTrue(result.details().stream().anyMatch(
                d -> d.contains("scenario awsKms ") && d.contains("java-v3->java-v3")),
            () -> "the awsKms hole must be reported: " + result.details());
    }

    @Test
    void onlyPassedExecutionsSatisfyTheFloor() {
        // A failed KMS execution does not provide coverage; the run reports both
        // the failure and the hole.
        List<String> targets = List.of("java-v3");
        List<TestExecution> executions = new ArrayList<>();
        for (String scenario : ResultReporter.REQUIRED_KMS_SCENARIOS) {
            executions.add(TestExecution.passed(
                "Tests#blob[" + scenario + "] java-v3->java-v3"));
        }
        // Replace the awsKmsDiscovery pass with a failure.
        executions.removeIf(e -> e.name().contains("[awsKmsDiscovery]"));
        executions.add(TestExecution.failed(
            "Tests#blob[awsKmsDiscovery] java-v3->java-v3", "decrypt mismatch"));

        Result result = reporter.report(executions, targets, NO_CLEANUP);
        assertFalse(result.succeeded());
        assertTrue(result.details().stream().anyMatch(
                d -> d.contains("awsKmsDiscovery") && d.contains("Requirement 10.4")),
            () -> "a failed KMS execution must still leave a coverage hole: "
                + result.details());
    }

    @Test
    void noLaunchedTargetsMakesTheFloorVacuous() {
        Result result = reporter.report(List.of(
                TestExecution.passed("Tests#blob[rawAes+default] java-v3->java-v3")),
            NO_TARGETS, NO_CLEANUP);
        assertTrue(result.succeeded(),
            () -> "with no launched targets the floor is vacuous: " + result);
    }

    // -------------------------------------------------------------------
    // Cleanup failures (Requirement 2.11).
    // -------------------------------------------------------------------

    @Test
    void cleanupFailuresAreAppendedWithoutMaskingSuccess() {
        List<String> targets = List.of("java-v3");
        Result result = reporter.report(
            fullKmsCoverage(targets), targets, List.of("python"));
        assertTrue(result.succeeded(),
            "a cleanup failure must not mask a passing primary result");
        assertTrue(result.details().stream().anyMatch(
                d -> d.contains("cleanup failure") && d.contains("python")),
            () -> "the cleanup failure must name the language: " + result.details());
        assertTrue(result.summary().contains("python"),
            () -> "the summary must surface the cleanup failure: " + result.summary());
    }

    @Test
    void cleanupFailuresAreAppendedToAFailedRunNamingEachLanguage() {
        Result result = reporter.report(List.of(
                TestExecution.failed("Tests#blob[rawAes+default] java-v3->java-v3", "boom")),
            NO_TARGETS, List.of("java", "python"));
        assertFalse(result.succeeded());
        for (String language : List.of("java", "python")) {
            assertTrue(result.details().stream().anyMatch(
                    d -> d.contains("cleanup failure") && d.contains(language)),
                () -> "each still-running language must be named: " + result.details());
        }
        // The primary failure is still reported first, unmasked.
        assertTrue(result.details().stream().anyMatch(d -> d.contains("boom")),
            () -> "the primary failure must remain in the report: " + result.details());
    }

    // -------------------------------------------------------------------
    // Helpers.
    // -------------------------------------------------------------------

    /**
     * One passed execution per (pair × required KMS scenario) over the full
     * pairwise product of {@code targets}, using the Tests' naming convention.
     */
    private static List<TestExecution> fullKmsCoverage(List<String> targets) {
        List<TestExecution> executions = new ArrayList<>();
        for (String encrypt : targets) {
            for (String decrypt : targets) {
                for (String scenario : ResultReporter.REQUIRED_KMS_SCENARIOS) {
                    executions.add(TestExecution.passed(
                        "Tests#blob[" + scenario + "] " + encrypt + "->" + decrypt));
                }
            }
        }
        return executions;
    }
}
