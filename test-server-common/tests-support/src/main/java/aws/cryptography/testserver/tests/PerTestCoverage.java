package aws.cryptography.testserver.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jacoco.core.tools.ExecDumpClient;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/**
 * Records which library lines each test ran, on every server that supports it.
 *
 * <p>After each test, this listener asks each server to write the coverage it
 * gathered since the last test to its own file, and to zero its counters.
 * That only works because the Tests run one at a time. The files go under
 * {@code <coverage dir>/<language>/tests/}, and
 * {@code <coverage dir>/tests.jsonl} gets one line naming the test, its result,
 * and its file number. {@code test-server-common/tools/per_test_coverage.py}
 * turns the files into line numbers after the run.
 *
 * <p>It runs when {@value #SWITCH_VARIABLE} is set and {@value #DIRECTORY_VARIABLE}
 * names the coverage directory the orchestrator wrote. The Tests must then run
 * one at a time. A language takes part when its {@code meta.json} there
 * names a tool with a per-test dump:
 * <ul>
 *   <li>{@code llvm} (Rust): the server answers {@code POST /control/coverage}
 *       with the file path as the body.</li>
 *   <li>{@code jacoco} (Java): the JaCoCo agent listens on
 *       {@code jacoco_port}, and this listener writes the file it sends.</li>
 * </ul>
 */
public final class PerTestCoverage implements TestExecutionListener {

    /** The environment variable naming the orchestrator's coverage directory. */
    public static final String DIRECTORY_VARIABLE = "TESTSERVER_COVERAGE_DIR";

    /** The environment variable that turns per-test coverage on. */
    public static final String SWITCH_VARIABLE = "TESTSERVER_PER_TEST_COVERAGE";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10)).build();

    private Path directory;
    private List<Server> servers = List.of();
    private BufferedWriter index;
    private int nextFile;
    private int running;
    private boolean warned;

    private record Server(LanguageServerTarget target, String tool, int jacocoPort, Path files) {
    }

    @Override
    public void testPlanExecutionStarted(TestPlan plan) {
        String value = System.getenv(DIRECTORY_VARIABLE);
        String on = System.getenv(SWITCH_VARIABLE);
        if (value == null || value.isBlank() || on == null || on.isBlank()) {
            return;
        }
        directory = Path.of(value);
        servers = servers(directory);
        if (servers.isEmpty()) {
            return;
        }
        try {
            index = Files.newBufferedWriter(directory.resolve("tests.jsonl"), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        // What the servers ran before the first test (starting up, the readiness
        // check) goes to its own file, so the first test is not charged for it.
        dumpAll("before-tests");
    }

    @Override
    public synchronized void executionStarted(TestIdentifier test) {
        if (index != null && test.isTest() && running++ > 0 && !warned) {
            warned = true;
            System.err.println("[per-test coverage] tests are running at the same time, so each test's"
                + " lines include lines from the others; turn off junit.jupiter.execution.parallel.enabled");
        }
    }

    @Override
    public synchronized void executionSkipped(TestIdentifier test, String reason) {
        if (index != null && test.isTest()) {
            record(test, "skipped", null);
        }
    }

    @Override
    public synchronized void executionFinished(TestIdentifier test, TestExecutionResult result) {
        if (index == null || !test.isTest()) {
            return;
        }
        running--;
        String file = String.valueOf(nextFile++);
        dumpAll(file);
        String status = switch (result.getStatus()) {
            case SUCCESSFUL -> "passed";
            case ABORTED -> "skipped";
            case FAILED -> "failed";
        };
        record(test, status, file);
    }

    @Override
    public void testPlanExecutionFinished(TestPlan plan) {
        if (index == null) {
            return;
        }
        try {
            index.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        index = null;
    }

    private void record(TestIdentifier test, String status, String file) {
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("test", testName(test));
        line.put("junit_id", test.getUniqueId());
        line.put("status", status);
        line.put("file", file);
        try {
            index.write(JSON.writeValueAsString(line));
            index.newLine();
            index.flush();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** {@code <class>#<display name>}, the way the JUnit XML names a test case. */
    static String testName(TestIdentifier test) {
        String className = test.getSource()
            .filter(MethodSource.class::isInstance)
            .map(source -> ((MethodSource) source).getClassName())
            .orElse("");
        return className + "#" + test.getDisplayName();
    }

    private void dumpAll(String file) {
        List<Server> failed = new ArrayList<>();
        for (Server server : servers) {
            try {
                Files.createDirectories(server.files());
                // Two targets of one language share the directory, so the label tells their files apart.
                String name = file + "." + server.target().label();
                switch (server.tool()) {
                    case "llvm" -> dumpLlvm(server, server.files().resolve(name + ".profraw"));
                    case "jacoco" -> dumpJacoco(server, server.files().resolve(name + ".exec"));
                    default -> throw new IllegalStateException(server.tool());
                }
            } catch (IOException e) {
                // A server built without the dump (for example the Dafny-generated Rust
                // servers) fails every time, so it is asked only once. Its tests show no lines.
                System.err.println("[per-test coverage] " + server.target().label()
                    + " gives no per-test coverage: " + e.getMessage());
                failed.add(server);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        if (!failed.isEmpty()) {
            servers = servers.stream().filter(server -> !failed.contains(server)).toList();
        }
    }

    private static void dumpLlvm(Server server, Path file) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(server.target().endpoint().resolve("/control/coverage"))
            .timeout(Duration.ofSeconds(60))
            .POST(HttpRequest.BodyPublishers.ofString(file.toAbsolutePath().toString()))
            .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("POST /control/coverage returned " + response.statusCode()
                + ": " + response.body());
        }
    }

    private static void dumpJacoco(Server server, Path file) throws IOException {
        ExecDumpClient client = new ExecDumpClient();
        client.setDump(true);
        client.setReset(true);
        client.dump(server.target().endpoint().getHost(), server.jacocoPort()).save(file.toFile(), false);
    }

    /** One entry per target whose language's meta.json names a tool with a per-test dump. */
    private static List<Server> servers(Path directory) {
        List<Server> servers = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().allTargets()) {
            Optional<JsonNode> meta = meta(directory.resolve(target.language()).resolve("meta.json"));
            if (meta.isEmpty()) {
                continue;
            }
            String tool = meta.get().path("tool").asText();
            int jacocoPort = meta.get().path("jacoco_port").asInt(0);
            if (tool.equals("llvm") || (tool.equals("jacoco") && jacocoPort > 0)) {
                servers.add(new Server(target, tool, jacocoPort,
                    directory.resolve(target.language()).resolve("tests")));
            }
        }
        return List.copyOf(servers);
    }

    private static Optional<JsonNode> meta(Path file) {
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        try {
            return Optional.of(JSON.readTree(file.toFile()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
