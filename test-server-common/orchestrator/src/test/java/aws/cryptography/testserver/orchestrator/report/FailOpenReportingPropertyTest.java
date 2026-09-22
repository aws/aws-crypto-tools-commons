package aws.cryptography.testserver.orchestrator.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for {@link ResultReporter} using jqwik (Property 14). Each
 * property runs a minimum of 100 generated iterations against the pure reporter
 * function over test-outcome sets (design Testing Strategy).
 *
 * <p>Also carries the test-server-factoring feature's Property 9 (fail-open
 * result classification over all four outcomes, including JUnit XML parse
 * fidelity through {@code GradleTestRunner.parseResults}).
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
                // Zero Tests executed is a failure.
                assertTrue(result.summary().toLowerCase().contains("no tests"),
                    "empty run must report zero tests executed: " + result.summary());
            } else {
                // Every failed / unreachable execution must be identified.
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
    // An unreachable server is never reported as a pass.
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void anyUnreachableIsAlwaysFailure(@ForAll("executionsWithUnreachable") List<TestExecution> executions) {
        Result result = reporter.report(executions);
        assertFalse(result.succeeded(),
            "a run containing an unreachable server must never be a pass (Requirement 13.3)");
    }

    // Feature: test-server-factoring, Property 9: Fail-open result classification
    // For any generated multiset of test executions (passed/failed/unreachable/
    // skipped): the orchestrator reports exactly one overall result, success iff
    // at least one execution is executed (skips excluded) and none is failed or
    // unreachable; every failure detail identifies the test and its (encrypt,
    // decrypt) combination; and parsing N JUnit testcase elements yields exactly
    // N executions, each with exactly one status, with <skipped> mapped to the
    // skipped outcome carrying its message.
    @Property(tries = 150, generation = GenerationMode.RANDOMIZED)
    void failOpenClassificationWithXmlParseFidelity(@ForAll("junitCases") List<JUnitCase> cases)
            throws IOException {
        Path resultsDir = Files.createTempDirectory("p9-junit-xml");
        try {
            Files.writeString(
                resultsDir.resolve("TEST-Tests.xml"), junitXml(cases), StandardCharsets.UTF_8);

            // --- JUnit XML parse fidelity -------------
            // N generated testcase elements yield exactly N executions, in
            // document order, each carrying exactly the one generated status.
            List<TestExecution> parsed = parseViaGradleTestRunner(resultsDir);
            assertEquals(cases.size(), parsed.size(),
                "parsing N testcase elements must yield exactly N executions (Requirement 9.10)");
            for (int i = 0; i < cases.size(); i++) {
                JUnitCase c = cases.get(i);
                TestExecution e = parsed.get(i);
                assertEquals("Tests#" + c.testName(), e.name(),
                    "each execution must identify its test case");
                assertEquals(c.expectedOutcome(), e.outcome(),
                    "each execution must carry exactly the generated status (Requirements 9.8, 9.10)");
                if (c.expectedOutcome() == TestExecution.Outcome.SKIPPED) {
                    // <skipped> maps to the skipped outcome carrying its message.
                    assertEquals(c.message(), e.detail(),
                        "a skipped execution must carry the <skipped message>");
                }
            }

            // --- Fail-open classification -
            // Empty launched-target set keeps the KMS floor vacuous (Property 10
            // covers the floor); no cleanup failures.
            Result result = reporter.report(parsed, List.of(), List.of());
            assertNotNull(result, "the orchestrator must report exactly one overall result");

            long executed = parsed.stream()
                .filter(e -> e.outcome() != TestExecution.Outcome.SKIPPED)
                .count();
            boolean anyBad = parsed.stream().anyMatch(
                e -> e.outcome() == TestExecution.Outcome.FAILED
                    || e.outcome() == TestExecution.Outcome.UNREACHABLE);
            boolean expectedSuccess = executed > 0 && !anyBad;
            assertEquals(expectedSuccess, result.succeeded(),
                "success iff >=1 executed (skips excluded, Requirement 2.8) and none "
                    + "failed/unreachable (Requirement 2.10); executed=" + executed
                    + ", anyBad=" + anyBad + ", summary=" + result.summary());

            for (int i = 0; i < cases.size(); i++) {
                JUnitCase c = cases.get(i);
                TestExecution e = parsed.get(i);
                if (e.outcome() == TestExecution.Outcome.FAILED
                        || e.outcome() == TestExecution.Outcome.UNREACHABLE) {
                    // Every failure detail identifies the test and, through the
                    // `…[<scenario>] <encrypt>-><decrypt>` naming, its combination.
                    String name = e.name();
                    assertTrue(result.details().stream().anyMatch(
                            d -> d.contains(name) && d.contains(c.pair())),
                        "failure details must identify the test and its (encrypt, decrypt) "
                            + "combination " + c.pair() + ": " + result.details());
                    if (e.outcome() == TestExecution.Outcome.UNREACHABLE) {
                        // The unresponsive server's test is identified and the run
                        // fails.
                        assertFalse(result.succeeded(),
                            "an unreachable execution must fail the run (Requirement 10.7)");
                        assertTrue(result.details().stream().anyMatch(
                                d -> d.contains(name) && d.contains(c.expectedDetail())),
                            "the unreachable detail must identify the unresponsive server "
                                + "for test " + name + ": " + result.details());
                    }
                }
            }
        } finally {
            deleteRecursively(resultsDir);
        }
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

    // ------------------------------------------------------------------------
    // Property 9 generators and helpers
    // ------------------------------------------------------------------------

    /**
     * Generate execution multisets across all four outcomes, with test names
     * following the Tests' {@code <mode>[<scenario>] <encrypt>-><decrypt>}
     * convention (duplicates allowed — it is a multiset). Kinds: 0 = passed,
     * 1 = failed via {@code <failure>}, 2 = failed via {@code <error>},
     * 3 = unreachable via a connection-refused {@code <error>}, 4 = skipped.
     */
    @Provide
    Arbitrary<List<JUnitCase>> junitCases() {
        Arbitrary<String> mode = Arbitraries.of("blob", "stream");
        Arbitrary<String> scenario = Arbitraries.of(
            "awsKms", "awsKmsMrk", "awsKmsMultiKeyring", "awsKmsRsa", "awsKmsDiscovery",
            "rawAes", "hierarchy");
        Arbitrary<String> target = Arbitraries.of("java-v3", "python-v4", "java-v2", "net-v4");
        Arbitrary<Integer> kind = Arbitraries.integers().between(0, 4);
        Arbitrary<JUnitCase> aCase = Combinators.combine(mode, scenario, target, target, kind)
            .as((m, s, enc, dec, k) -> {
                String pair = enc + "->" + dec;
                String testName = m + "[" + s + "] " + pair;
                // Failure messages deliberately avoid the parser's
                // unreachable-classification keywords; the unreachable message
                // deliberately includes one.
                String message = switch (k) {
                    case 1 -> "round-trip bytes differed for " + pair;
                    case 2 -> "handler raised: bad ciphertext for " + pair;
                    case 3 -> "Connection refused: " + enc + " Language_Server";
                    case 4 -> "feature-gated skip: feature=streaming unsupported by [" + dec + "]";
                    default -> "";
                };
                return new JUnitCase(testName, pair, k, message);
            });
        return aCase.list().ofMaxSize(10);
    }

    /**
     * One generated JUnit {@code testcase}: its name (embedding the (encrypt,
     * decrypt) combination as {@code pair}), its status kind, and the message
     * its status element carries.
     */
    private record JUnitCase(String testName, String pair, int kind, String message) {

        TestExecution.Outcome expectedOutcome() {
            return switch (kind) {
                case 0 -> TestExecution.Outcome.PASSED;
                case 1, 2 -> TestExecution.Outcome.FAILED;
                case 3 -> TestExecution.Outcome.UNREACHABLE;
                default -> TestExecution.Outcome.SKIPPED;
            };
        }

        String type() {
            return switch (kind) {
                case 1 -> "org.opentest4j.AssertionFailedError";
                case 2 -> "java.lang.IllegalStateException";
                case 3 -> "java.net.ConnectException";
                default -> "";
            };
        }

        /** The detail {@code GradleTestRunner.parseResults} derives for this case. */
        String expectedDetail() {
            return switch (kind) {
                case 0 -> "";
                case 4 -> message;
                default -> type() + ": " + message;
            };
        }

        /** The testcase XML element, carrying exactly one status. */
        String toXml() {
            String open = "  <testcase classname=\"Tests\" name=\"" + testName + "\" time=\"0.01\"";
            return switch (kind) {
                case 0 -> open + "/>\n";
                case 1 -> open + ">\n    <failure message=\"" + message + "\" type=\"" + type()
                    + "\">" + type() + ": " + message + "</failure>\n  </testcase>\n";
                case 2, 3 -> open + ">\n    <error message=\"" + message + "\" type=\"" + type()
                    + "\">" + type() + ": " + message + "</error>\n  </testcase>\n";
                default -> open + ">\n    <skipped message=\"" + message + "\"/>\n  </testcase>\n";
            };
        }
    }

    /** Render a whole JUnit result file for the generated testcases. */
    private static String junitXml(List<JUnitCase> cases) {
        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            .append("<testsuite name=\"Tests\" tests=\"").append(cases.size()).append("\">\n");
        for (JUnitCase c : cases) {
            xml.append(c.toXml());
        }
        return xml.append("</testsuite>\n").toString();
    }

    /**
     * Invoke {@code GradleTestRunner.parseResults(Path)} reflectively: the
     * method is package-private in the {@code run} package while this test —
     * the single home of the fail-open classification property — lives in the
     * {@code report} package next to the reporter it exercises.
     */
    @SuppressWarnings("unchecked")
    private static List<TestExecution> parseViaGradleTestRunner(Path resultsDir) {
        try {
            Class<?> runner = Class.forName(
                "aws.cryptography.testserver.orchestrator.run.GradleTestRunner");
            Method parseResults = runner.getDeclaredMethod("parseResults", Path.class);
            parseResults.setAccessible(true);
            return (List<TestExecution>) parseResults.invoke(null, resultsDir);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                "failed to invoke GradleTestRunner.parseResults reflectively", e);
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
    }
}
