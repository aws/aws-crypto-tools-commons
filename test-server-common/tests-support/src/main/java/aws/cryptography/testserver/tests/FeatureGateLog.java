package aws.cryptography.testserver.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/**
 * Writes one JSON line per {@link FeatureGate#require} call, so a report can
 * tell which Features each test run needed from each target. JUnit's own XML
 * only names a Feature when the gate skips a test; a passing test leaves no
 * trace of the Features it used.
 *
 * <p>Each line is {@code {"id", "name", "targets", "features", "result"}}:
 * the JUnit unique id and display name of the running test, the labels of the
 * targets the call gated, the Features it required, and {@code run},
 * {@code skipped} or {@code error}. A {@link DryRun} adds a
 * {@value DryRun#WOULD_RUN} line, with no targets or Features, when a test
 * reaches its first server call. The display name matches the
 * {@code testcase name} in the JUnit XML, and the unique id names the test
 * class, so the two files join on (class, name).
 *
 * <p>The JUnit Platform launcher loads this listener through
 * {@code META-INF/services}. It writes only when the system property
 * {@value #PATH_PROPERTY} names a file, which it replaces at the start of each
 * test plan. The launcher reports a test's start on the thread that runs it,
 * so a per-thread stack of running tests tells the gate which test called it,
 * including dynamic and concurrently run tests.
 */
public final class FeatureGateLog implements TestExecutionListener {

    /** System property naming the JSON Lines file to write. */
    public static final String PATH_PROPERTY = "testserver.featureGateLog";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ThreadLocal<Deque<TestIdentifier>> RUNNING =
        ThreadLocal.withInitial(ArrayDeque::new);
    private static BufferedWriter out;

    @Override
    public void testPlanExecutionStarted(TestPlan plan) {
        String path = System.getProperty(PATH_PROPERTY);
        if (path == null || path.isBlank()) {
            return;
        }
        try {
            Path file = Path.of(path);
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            synchronized (FeatureGateLog.class) {
                out = Files.newBufferedWriter(file, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open " + PATH_PROPERTY + "=" + path, e);
        }
    }

    @Override
    public void testPlanExecutionFinished(TestPlan plan) {
        synchronized (FeatureGateLog.class) {
            if (out == null) {
                return;
            }
            try {
                out.close();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } finally {
                out = null;
            }
        }
    }

    @Override
    public void executionStarted(TestIdentifier test) {
        RUNNING.get().push(test);
    }

    @Override
    public void executionFinished(TestIdentifier test, TestExecutionResult result) {
        RUNNING.get().remove(test);
    }

    /** Called by the gate for every decision, before it returns or throws. */
    static void record(List<LanguageServerTarget> targets, List<String> features, String result) {
        TestIdentifier test = RUNNING.get().peek();
        synchronized (FeatureGateLog.class) {
            if (out == null || test == null) {
                return;
            }
            Map<String, Object> line = new LinkedHashMap<>();
            line.put("id", test.getUniqueId());
            line.put("name", test.getDisplayName());
            line.put("targets", targets.stream().map(LanguageServerTarget::label).toList());
            line.put("features", features);
            line.put("result", result);
            try {
                out.write(JSON.writeValueAsString(line));
                out.newLine();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
