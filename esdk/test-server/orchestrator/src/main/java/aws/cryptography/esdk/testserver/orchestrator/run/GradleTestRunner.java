package aws.cryptography.esdk.testserver.orchestrator.run;

import aws.cryptography.esdk.testserver.orchestrator.report.TestExecution;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Runs the single Java {@code Tests} suite by invoking its Gradle build as a
 * subprocess, pointing it at the launched endpoints purely through the
 * {@code esdk.testserver.endpoints} runtime property (Requirements 7.2, 7.3) —
 * the same mechanism the {@code make test-live} target uses. The Tests definition
 * is never altered per language.
 *
 * <p>Refuses to run and records no partial results when no endpoint is configured
 * (Requirement 7.4). After the run it parses the JUnit XML result files into
 * {@link TestExecution}s so the fail-open reporter can decide the outcome; a test
 * that failed because a server was unreachable is classified as
 * {@link TestExecution.Outcome#UNREACHABLE} (Requirement 13.3).
 */
public final class GradleTestRunner implements TestRunner {

    private final Path testsModuleDir;
    private volatile String lastOutput = "";

    public GradleTestRunner(Path testsModuleDir) {
        this.testsModuleDir = testsModuleDir;
    }

    /** @return the captured stdout/stderr of the most recent Gradle run (for diagnostics). */
    public String lastOutput() {
        return lastOutput;
    }

    @Override
    public List<TestExecution> run(List<URI> endpoints) throws MissingRuntimeConfigException {
        if (endpoints == null || endpoints.isEmpty()) {
            throw new MissingRuntimeConfigException(
                "no target endpoint configured for the Tests; refusing to run (Requirement 7.4)");
        }
        String csv = endpoints.stream().map(URI::toString).collect(Collectors.joining(","));

        String gradlew = new File(testsModuleDir.toFile(), "gradlew").getAbsolutePath();
        List<String> command = List.of(
            gradlew,
            "cleanTest", "test",
            "-Desdk.testserver.endpoints=" + csv,
            "--console=plain");

        ProcessBuilder pb = new ProcessBuilder(command)
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

    /** Parse every JUnit {@code TEST-*.xml} in {@code resultsDir} into executions. */
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
                    Element tc = (Element) cases.item(i);
                    TestExecution execution = toExecution(tc);
                    // A null execution marks a skipped (not executed) test, which
                    // is excluded from the executed-test set (Requirement 13.1).
                    if (execution != null) {
                        executions.add(execution);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("failed to parse Tests results in " + resultsDir, e);
        }
        return executions;
    }

    private static TestExecution toExecution(Element testcase) {
        String name = testcase.getAttribute("classname") + "#" + testcase.getAttribute("name");

        // A skipped testcase was not executed; omit it by treating it as a pass
        // only if it truly ran. We drop skipped by returning a PASSED marker? No:
        // reflect reality — skipped tests are not counted as executed. We model
        // that by NOT emitting them; callers filter nulls.
        if (hasChild(testcase, "skipped")) {
            return null;
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

    private static boolean hasChild(Element parent, String tag) {
        return firstChild(parent, tag) != null;
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
