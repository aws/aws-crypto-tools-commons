package aws.cryptography.esdk.testserver.orchestrator.report;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for {@link ResultReporter} using jqwik (Property 14). Each
 * property runs a minimum of 100 generated iterations against the pure reporter
 * function over test-outcome sets (design Testing Strategy).
 */
class FailOpenReportingPropertyTest {

    private final ResultReporter reporter = new ResultReporter();

    // Feature: esdk-test-server, Property 14: Fail-open result reporting
    // Success iff at least one Test executed and every executed Test passed.
    @Property(tries = 300, generation = GenerationMode.RANDOMIZED)
    void successIffNonEmptyAndAllPassed(@ForAll("executions") List<TestExecution> executions) {
        Result result = reporter.report(executions);

        boolean nonEmpty = !executions.isEmpty();
        boolean allPassed = executions.stream()
            .allMatch(e -> e.outcome() == TestExecution.Outcome.PASSED);
        boolean expectedSuccess = nonEmpty && allPassed;

        assertTrue(result.succeeded() == expectedSuccess,
            "success must hold iff >=1 executed and all passed (nonEmpty=" + nonEmpty
                + ", allPassed=" + allPassed + ")");

        if (!expectedSuccess) {
            assertFalse(result.succeeded(), "a failing/empty run must be a failure");
            if (!nonEmpty) {
                // Zero Tests executed is a failure (Requirement 13.4).
                assertTrue(result.summary().toLowerCase().contains("no tests"),
                    "empty run must report zero tests executed: " + result.summary());
            } else {
                // Every failed / unreachable execution must be identified (Req 13.2, 13.3).
                for (TestExecution e : executions) {
                    if (e.outcome() != TestExecution.Outcome.PASSED) {
                        boolean identified = result.details().stream()
                            .anyMatch(d -> d.contains(e.name()));
                        assertTrue(identified,
                            "failure must identify the failed/unreachable Test " + e.name()
                                + " in details " + result.details());
                    }
                }
            }
        }
    }

    // Feature: esdk-test-server, Property 14: Fail-open result reporting
    // An unreachable server is never reported as a pass (Requirement 13.3).
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void anyUnreachableIsAlwaysFailure(@ForAll("executionsWithUnreachable") List<TestExecution> executions) {
        Result result = reporter.report(executions);
        assertFalse(result.succeeded(),
            "a run containing an unreachable server must never be a pass (Requirement 13.3)");
    }

    @Provide
    Arbitrary<List<TestExecution>> executions() {
        return execution().list().ofMaxSize(12);
    }

    @Provide
    Arbitrary<List<TestExecution>> executionsWithUnreachable() {
        Arbitrary<List<TestExecution>> base = execution().list().ofMinSize(0).ofMaxSize(8);
        Arbitrary<TestExecution> unreachable = Arbitraries.integers().between(0, 999)
            .map(i -> TestExecution.unreachable("test-" + i, "server-" + i));
        return base.flatMap(list -> unreachable.map(u -> {
            java.util.List<TestExecution> withU = new java.util.ArrayList<>(list);
            withU.add(u);
            return List.copyOf(withU);
        }));
    }

    @Provide
    Arbitrary<TestExecution> execution() {
        Arbitrary<Integer> id = Arbitraries.integers().between(0, 999);
        Arbitrary<Integer> kind = Arbitraries.integers().between(0, 2);
        return id.flatMap(i -> kind.map(k -> switch (k) {
            case 0 -> TestExecution.passed("test-" + i);
            case 1 -> TestExecution.failed("test-" + i, "assertion failed");
            default -> TestExecution.unreachable("test-" + i, "server-" + i);
        }));
    }
}
