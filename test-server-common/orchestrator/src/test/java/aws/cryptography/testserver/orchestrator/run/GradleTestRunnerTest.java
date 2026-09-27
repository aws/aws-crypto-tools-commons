package aws.cryptography.testserver.orchestrator.run;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.report.TestExecution;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link GradleTestRunner}'s command construction (the three
 * runtime properties) and JUnit XML parsing: N {@code testcase} elements yield
 * exactly N {@link TestExecution}s with exactly one status each, and
 * {@code <skipped message>} maps to {@link TestExecution#skipped}.
 */
class GradleTestRunnerTest {

    // ---- command construction -------------------------------------------

    @Test
    @DisplayName("command passes targets, features, featureCatalog, and referenceImplementation properties (Req 2.2, 9.3)")
    void commandCarriesAllThreeProperties() {
        TestRunInput input = new TestRunInput(
            List.of(new TestTarget("java", 3, "dbe", URI.create("http://127.0.0.1:8091")),
                new TestTarget("python", 4, "dbe", URI.create("http://127.0.0.1:8092"))),
            features(),
            List.of("streaming", "MPL"),
            Map.of("c:1:dbe", List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1")),
            "java");

        List<String> command = GradleTestRunner.command(Path.of("tests"), input, "");

        assertTrue(command.contains(
                "-Dtestserver.targets=java:3:dbe=http://127.0.0.1:8091,python:4:dbe=http://127.0.0.1:8092"),
            "must pass the targets property: " + command);
        assertTrue(command.contains(
                "-Dtestserver.features=java:3:dbe:streaming=true;MPL=true,python:4:dbe:streaming=true;MPL=true"),
            "must pass the flattened features property: " + command);
        assertTrue(command.contains("-Dtestserver.featureCatalog=streaming,MPL"),
            "must pass the catalog verbatim: " + command);
        assertTrue(command.contains(
                "-Dtestserver.rawRsaPaddingSchemes=c:1:dbe:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1"),
            "must pass the declared padding capabilities: " + command);
        assertTrue(command.contains("-Dtestserver.referenceImplementation=java"),
            "must pass the reference implementation: " + command);
        assertTrue(command.stream().noneMatch(a -> a.startsWith("-Dtestserver.endpoints")),
            "the legacy endpoints property is replaced: " + command);
    }

    @Test
    @DisplayName("empty feature inputs omit the feature properties, never pass blanks")
    void commandOmitsEmptyFeatureProperties() {
        TestRunInput input = new TestRunInput(
            List.of(new TestTarget("java", 3, "dbe", URI.create("http://127.0.0.1:8091"))),
            Map.of(),
            List.of(),
            Map.of(),
            "java");

        List<String> command = GradleTestRunner.command(Path.of("tests"), input, "");

        assertTrue(command.stream().anyMatch(a -> a.startsWith("-Dtestserver.targets=")));
        assertTrue(command.stream().noneMatch(a -> a.startsWith("-Dtestserver.features")),
            "no features property when none are on hand: " + command);
        assertTrue(command.stream()
                .noneMatch(a -> a.startsWith("-Dtestserver.rawRsaPaddingSchemes")),
            "no padding property when no language declares one: " + command);
    }

    @Test
    @DisplayName("a focus is passed as testserver.focus; no focus passes nothing")
    void commandCarriesTheFocus() {
        TestRunInput input = new TestRunInput(
            List.of(new TestTarget("java", 3, "dbe", URI.create("http://127.0.0.1:8091"))),
            Map.of(), List.of(), Map.of(), "java");

        assertTrue(GradleTestRunner.command(Path.of("tests"), input, "", "rust,rust-cpp")
            .contains("-Dtestserver.focus=rust,rust-cpp"));
        assertTrue(GradleTestRunner.command(Path.of("tests"), input, "").stream()
            .noneMatch(a -> a.startsWith("-Dtestserver.focus")));
    }

    // ---- JUnit XML parsing ----------------------------------------------

    @Test
    @DisplayName("N testcase elements yield exactly N executions with exactly one status each (Req 9.10)")
    void parsesOneExecutionPerTestcase(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("TEST-RoundTrip.xml"), """
            <?xml version="1.0" encoding="UTF-8"?>
            <testsuite name="RoundTrip" tests="4">
              <testcase classname="RoundTrip" name="passes"/>
              <testcase classname="RoundTrip" name="fails">
                <failure message="expected X but was Y" type="org.opentest4j.AssertionFailedError">stack</failure>
              </testcase>
              <testcase classname="RoundTrip" name="unreachable">
                <error message="Connection refused" type="java.net.ConnectException">stack</error>
              </testcase>
              <testcase classname="RoundTrip" name="gated">
                <skipped message="feature-gated skip: feature=streaming unsupported by [rust]"/>
              </testcase>
            </testsuite>
            """.stripIndent());

        List<TestExecution> executions = GradleTestRunner.parseResults(dir);

        assertEquals(4, executions.size(),
            "4 testcase elements must yield exactly 4 executions");
        assertEquals(TestExecution.Outcome.PASSED, byName(executions, "passes").outcome());
        assertEquals(TestExecution.Outcome.FAILED, byName(executions, "fails").outcome());
        assertEquals(TestExecution.Outcome.UNREACHABLE, byName(executions, "unreachable").outcome());
        assertEquals(TestExecution.Outcome.SKIPPED, byName(executions, "gated").outcome());
    }

    @Test
    @DisplayName("<skipped message> maps to TestExecution.skipped carrying the message (Req 9.6)")
    void skippedCarriesTheMessage(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("TEST-Stream.xml"), """
            <?xml version="1.0" encoding="UTF-8"?>
            <testsuite name="Stream" tests="1">
              <testcase classname="Stream" name="streamRoundTrip">
                <skipped message="feature-gated skip: feature=streaming unsupported by [python]"/>
              </testcase>
            </testsuite>
            """.stripIndent());

        List<TestExecution> executions = GradleTestRunner.parseResults(dir);

        assertEquals(1, executions.size(), "the skipped testcase must not be dropped");
        TestExecution skipped = executions.get(0);
        assertEquals(TestExecution.Outcome.SKIPPED, skipped.outcome());
        assertEquals("feature-gated skip: feature=streaming unsupported by [python]",
            skipped.detail(), "the skip message must be carried");
        assertEquals("Stream#streamRoundTrip", skipped.name());
    }

    @Test
    @DisplayName("a results directory with no XML yields zero executions")
    void emptyResultsDirectoryYieldsNoExecutions(@TempDir Path dir) {
        assertEquals(List.of(), GradleTestRunner.parseResults(dir));
        assertEquals(List.of(), GradleTestRunner.parseResults(dir.resolve("missing")));
    }

    private static TestExecution byName(List<TestExecution> executions, String shortName) {
        return executions.stream()
            .filter(e -> e.name().endsWith("#" + shortName))
            .findFirst()
            .orElseThrow(() -> new AssertionError(
                "no execution named " + shortName + " in " + executions));
    }

    private static Map<String, Map<String, Boolean>> features() {
        Map<String, Boolean> both = new LinkedHashMap<>();
        both.put("streaming", true);
        both.put("MPL", true);
        Map<String, Map<String, Boolean>> features = new LinkedHashMap<>();
        features.put("java:3:dbe", both);
        features.put("python:4:dbe", both);
        return features;
    }
}
