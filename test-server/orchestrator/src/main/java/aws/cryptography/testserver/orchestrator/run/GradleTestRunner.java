package aws.cryptography.testserver.orchestrator.run;

import aws.cryptography.testserver.orchestrator.report.TestExecution;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Runs the single Java {@code Tests} suite by invoking its Gradle build as a
 * subprocess, pointing it at the launched Targets purely through runtime
 * properties (Requirement 10.2; design "Runtime properties handed to the
 * Tests"):
 *
 * <ul>
 *   <li>{@code -Dtestserver.targets=<lang>:<major>=<url>,...} — the
 *       launched Targets (Requirement 2.2),</li>
 *   <li>{@code -Dtestserver.features=...} — each language's
 *       Feature_Declaration flattened to booleans (Requirement 9.3),</li>
 *   <li>{@code -Dtestserver.featureCatalog=...} — the Feature_Catalog
 *       verbatim,</li>
 *   <li>{@code -Dtestserver.rawRsaPaddingSchemes=...} — each language's
 *       declared raw-RSA padding capability (only languages that declare one;
 *       an absent language supports every scheme),</li>
 *   <li>{@code -Dtestserver.referenceImplementation=...} — the validated
 *       reference implementation language (single-sided Tests produce their
 *       messages on its Language_Server).</li>
 * </ul>
 *
 * The Tests definition is never altered per language.
 *
 * <p>Refuses to run and records no partial results when no Target is configured.
 * After the run it parses the JUnit XML result files into {@link TestExecution}s
 * so the fail-open reporter can decide the outcome: parsing N {@code testcase}
 * elements yields exactly N executions with exactly one status each
 * (Requirement 9.10). A {@code <skipped message>} maps to
 * {@link TestExecution#skipped} so skips are reported distinctly
 * (Requirement 9.6) and excluded from the executed set (Requirement 2.8); a
 * test that failed because a server was unreachable is classified as
 * {@link TestExecution.Outcome#UNREACHABLE} (Requirement 10.7).
 */
public final class GradleTestRunner implements TestRunner {

    /** Runtime-config key: comma-separated {@code language:major=url} target entries. */
    public static final String TARGETS_PROPERTY = "testserver.targets";

    /** Runtime-config key: comma-separated {@code lang:feat=bool[;feat=bool…]} entries. */
    public static final String FEATURES_PROPERTY = "testserver.features";

    /** Runtime-config key: comma-separated Feature_Catalog names. */
    public static final String FEATURE_CATALOG_PROPERTY = "testserver.featureCatalog";

    /** Runtime-config key: comma-separated {@code lang:SCHEME[;SCHEME…]} entries. */
    public static final String RAW_RSA_PADDING_SCHEMES_PROPERTY =
        "testserver.rawRsaPaddingSchemes";

    /** Runtime-config key: comma-separated {@code lang:id[;id…]} exhibited-bug entries. */
    public static final String KNOWN_BUGS_PROPERTY = "testserver.knownBugs";

    /** Runtime-config key: the reference implementation's language. */
    public static final String REFERENCE_IMPLEMENTATION_PROPERTY =
        "testserver.referenceImplementation";

    private final Path testsModuleDir;
    private volatile String lastOutput = "";

    /**
     * Optional {@code --tests <pattern>} filter passed verbatim to the child
     * Gradle {@code test} task. Empty (the default) runs every test class.
     * Set via {@link #withTestFilter(String)}.
     */
    private volatile String testFilter = "";

    public GradleTestRunner(Path testsModuleDir) {
        this.testsModuleDir = testsModuleDir;
    }

    /**
     * Restrict the JUnit run to {@code pattern} — passed verbatim to
     * {@code ./gradlew test --tests <pattern>}. Empty / null restores the
     * default of "run every test class". Purpose: scope one orchestrated run
     * to a single class (e.g. {@code TamperTest}) so there is no need for
     * per-suite make targets.
     *
     * @return this runner, for chaining
     */
    public GradleTestRunner withTestFilter(String pattern) {
        this.testFilter = pattern == null ? "" : pattern.trim();
        return this;
    }

    /** @return the configured test filter, empty when unset. */
    public String testFilter() {
        return testFilter;
    }

    /** @return the captured stdout/stderr of the most recent Gradle run (for diagnostics). */
    public String lastOutput() {
        return lastOutput;
    }

    @Override
    public List<TestExecution> run(TestRunInput input) throws MissingRuntimeConfigException {
        if (input == null || input.targets().isEmpty()) {
            throw new MissingRuntimeConfigException(
                "no target endpoint configured for the Tests; refusing to run (Requirement 10.2)");
        }

        ProcessBuilder pb = new ProcessBuilder(command(testsModuleDir, input, testFilter))
            .directory(testsModuleDir.toFile())
            .redirectErrorStream(true);
        // Inherit the environment (notably JAVA_HOME resolved to a JDK 21+).

        try {
            Process process = pb.start();
            StringBuilder out = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    out.append(line).append('\n');
                }
            }
            process.waitFor();
            lastOutput = out.toString();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to launch the Tests Gradle run", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("interrupted while running the Tests", e);
        }

        return parseResults(testsModuleDir.resolve("build/test-results/test"));
    }

    /**
     * Build the Gradle command line for {@code input}. The feature properties
     * are passed whenever present; on the Tests side an absent property
     * surfaces as a configuration error only when a Feature-gated Test queries
     * it (never an assumption, Requirement 9.3). Static so the pipeline
     * (task 9.1) and tests can inspect the exact invocation. When
     * {@code testFilter} is non-blank it becomes a {@code --tests <filter>}
     * argument passed verbatim to the child Gradle test task.
     */
    static List<String> command(Path testsModuleDir, TestRunInput input, String testFilter) {
        String gradlew = new File(testsModuleDir.toFile(), "gradlew").getAbsolutePath();
        List<String> command = new ArrayList<>(List.of(
            gradlew,
            "cleanTest", "test",
            "-D" + TARGETS_PROPERTY + "=" + TestRunInput.formatTargets(input.targets())));
        if (!input.features().isEmpty()) {
            command.add("-D" + FEATURES_PROPERTY + "="
                + TestRunInput.formatFeatures(input.features()));
        }
        if (!input.featureCatalog().isEmpty()) {
            command.add("-D" + FEATURE_CATALOG_PROPERTY + "="
                + TestRunInput.formatFeatureCatalog(input.featureCatalog()));
        }
        if (!input.rawRsaPaddingSchemes().isEmpty()) {
            command.add("-D" + RAW_RSA_PADDING_SCHEMES_PROPERTY + "="
                + TestRunInput.formatRawRsaPaddingSchemes(input.rawRsaPaddingSchemes()));
        }
        if (!input.knownBugs().isEmpty()) {
            command.add("-D" + KNOWN_BUGS_PROPERTY + "="
                + TestRunInput.formatKnownBugs(input.knownBugs()));
        }
        command.add("-D" + REFERENCE_IMPLEMENTATION_PROPERTY + "="
            + input.referenceImplementation());
        command.add("--console=plain");
        if (testFilter != null && !testFilter.isBlank()) {
            command.add("--tests");
            command.add(testFilter.trim());
        }
        return command;
    }

    /**
     * Parse every JUnit {@code TEST-*.xml} in {@code resultsDir} into executions:
     * N {@code testcase} elements yield exactly N {@link TestExecution}s, each
     * with exactly one status (Requirement 9.10).
     */
    static List<TestExecution> parseResults(Path resultsDir) {
        List<TestExecution> executions = new ArrayList<>();
        if (!Files.isDirectory(resultsDir)) {
            return executions;
        }
        try (Stream<Path> files = Files.list(resultsDir)) {
            List<Path> xmls = files
                .filter(p -> p.getFileName().toString().endsWith(".xml"))
                .sorted()
                .toList();
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            for (Path xml : xmls) {
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(xml.toFile());
                NodeList cases = doc.getElementsByTagName("testcase");
                for (int i = 0; i < cases.getLength(); i++) {
                    executions.add(toExecution((Element) cases.item(i)));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("failed to parse Tests results in " + resultsDir, e);
        }
        return executions;
    }

    private static TestExecution toExecution(Element testcase) {
        String name = testcase.getAttribute("classname") + "#" + testcase.getAttribute("name");

        // A skipped test case was not executed; record it distinctly, carrying
        // the skip message (e.g. the Feature-gated skip reason) so the report
        // can identify the Feature and languages (Requirements 9.6, 2.8).
        Element skipped = firstChild(testcase, "skipped");
        if (skipped != null) {
            return TestExecution.skipped(name, skipped.getAttribute("message"));
        }

        Element failure = firstChild(testcase, "failure");
        Element error = firstChild(testcase, "error");
        Element problem = failure != null ? failure : error;
        if (problem == null) {
            return TestExecution.passed(name);
        }

        String message = problem.getAttribute("message");
        String type = problem.getAttribute("type");
        String body = problem.getTextContent();
        String detail = (type.isBlank() ? "" : type + ": ") + message;
        String haystack = (detail + " " + body).toLowerCase(Locale.ROOT);

        if (haystack.contains("connection refused")
            || haystack.contains("connectexception")
            || haystack.contains("failed to connect")
            || haystack.contains("unreachable")
            || haystack.contains("no route to host")
            || haystack.contains("connect timed out")) {
            return TestExecution.unreachable(name, detail);
        }
        return TestExecution.failed(name, detail);
    }

    private static Element firstChild(Element parent, String tag) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && tag.equals(n.getNodeName())) {
                return (Element) n;
            }
        }
        return null;
    }
}
