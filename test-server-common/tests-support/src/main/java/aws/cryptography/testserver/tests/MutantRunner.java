package aws.cryptography.testserver.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherConfig;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

/**
 * Runs the Tests against mutants, for {@code test-server-common/tools/mutation/mutate.py}.
 *
 * <p>Usage: {@code java -cp <Tests class path> aws.cryptography.testserver.tests.MutantRunner <plan.json> <results.jsonl>}
 *
 * <p>The plan names the running mutated servers and, for each mutant, the
 * Tests to try in order. For each mutant this turns the mutant on in every
 * server ({@code POST /control/mutant}), runs its Tests one at a time, and
 * stops at the first failure: the mutant is killed. A mutant no test fails has
 * survived. With {@code stop_at_first_kill} false it runs every listed test,
 * which only measures what stopping early saves. Each result is one line of
 * {@code results.jsonl}.
 *
 * <p>One JVM runs every mutant, so the JVM and the Tests' clients start once.
 * A test that runs past the timeout usually means the mutant made the server
 * loop forever. Then this writes {@code timed_out} and exits with status 3, so
 * mutate.py can restart the server and run the rest of the plan.
 */
public final class MutantRunner {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    static final int TIMED_OUT_EXIT = 3;

    private MutantRunner() {
    }

    public static void main(String[] args) throws Exception {
        JsonNode plan = JSON.readTree(Path.of(args[0]).toFile());
        Path results = Path.of(args[1]);
        plan.path("system_properties").fields()
            .forEachRemaining(property -> System.setProperty(property.getKey(), property.getValue().asText()));
        List<URI> servers = new ArrayList<>();
        plan.path("servers").forEach(server -> servers.add(URI.create(server.asText())));
        Duration timeout = Duration.ofSeconds(plan.path("timeout_seconds").asLong(60));
        boolean stopAtFirstKill = plan.path("stop_at_first_kill").asBoolean(true);

        // The services-file listeners (feature gate log, per-test coverage) are for
        // the normal run; here they would overwrite that run's files.
        Launcher launcher = LauncherFactory.create(LauncherConfig.builder()
            .enableTestExecutionListenerAutoRegistration(false).build());
        ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "mutant-test");
            thread.setDaemon(true);
            return thread;
        });
        try (BufferedWriter out = Files.newBufferedWriter(results, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            for (JsonNode mutant : plan.path("mutants")) {
                int id = mutant.path("id").asInt();
                turnOn(servers, id);
                long started = System.nanoTime();
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("id", id);
                result.put("status", "survived");
                int run = 0;
                for (JsonNode test : mutant.path("tests")) {
                    run++;
                    String outcome = runOne(launcher, worker, test.asText(), timeout);
                    if (!outcome.equals("passed") && result.get("status").equals("survived")) {
                        result.put("status", outcome);
                        result.put("killed_by", test.asText());
                    }
                    if (!result.get("status").equals("survived") && (stopAtFirstKill || outcome.equals("timed_out"))) {
                        break;
                    }
                }
                result.put("tests_run", run);
                result.put("seconds", (System.nanoTime() - started) / 1e9);
                out.write(JSON.writeValueAsString(result));
                out.newLine();
                out.flush();
                if (result.get("status").equals("timed_out")) {
                    System.exit(TIMED_OUT_EXIT);
                }
            }
            turnOn(servers, 0);
        }
        System.exit(0);
    }

    /** {@code passed}, {@code killed} (the test failed) or {@code timed_out}. */
    private static String runOne(Launcher launcher, ExecutorService worker, String uniqueId, Duration timeout)
            throws Exception {
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
            .selectors(DiscoverySelectors.selectUniqueId(uniqueId)).build();
        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        Future<?> running = worker.submit(() -> launcher.execute(request, listener));
        try {
            running.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            return "timed_out";
        }
        TestExecutionSummary summary = listener.getSummary();
        if (summary.getTestsFoundCount() == 0) {
            throw new IllegalStateException("no test has the unique id " + uniqueId);
        }
        return summary.getTotalFailureCount() > 0 ? "killed" : "passed";
    }

    private static void turnOn(List<URI> servers, int id) throws IOException, InterruptedException {
        for (URI server : servers) {
            HttpRequest request = HttpRequest.newBuilder(server.resolve("/control/mutant"))
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(String.valueOf(id))).build();
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("POST " + request.uri() + " returned " + response.statusCode()
                    + ": " + response.body());
            }
        }
    }
}
