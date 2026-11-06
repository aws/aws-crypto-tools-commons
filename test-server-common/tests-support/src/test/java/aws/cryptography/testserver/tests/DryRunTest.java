package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

/**
 * Runs {@link Fixture} as a dry run and checks the log names each test that
 * reached a client as {@code would-run}, and none that a gate skipped.
 */
class DryRunTest {

    static final TestServerClientCache<Object> CLIENTS = new TestServerClientCache<>(uri -> {
        throw new AssertionError("a dry run must not build a client");
    });
    static final URI ENDPOINT = URI.create("http://dry-run.invalid:1");

    @Test
    void logsTestsThatReachAClient(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("gate.jsonl");
        System.setProperty(FeatureGateLog.PATH_PROPERTY, log.toString());
        System.setProperty(DryRun.PROPERTY, "true");
        try {
            LauncherFactory.create().execute(LauncherDiscoveryRequestBuilder.request()
                .selectors(selectClass(Fixture.class))
                .build());
        } finally {
            System.clearProperty(FeatureGateLog.PATH_PROPERTY);
            System.clearProperty(DryRun.PROPERTY);
        }

        ObjectMapper json = new ObjectMapper();
        Set<String> lines = new TreeSet<>();
        for (String line : Files.readAllLines(log)) {
            Map<?, ?> m = json.readValue(line, Map.class);
            lines.add(m.get("name") + " " + m.get("result"));
        }
        assertEquals(Set.of(
            "gatedThenClient() run",
            "gatedThenClient() would-run",
            "skippedByGate() skipped",
            "clientInsideAssertThrows() would-run",
            "noGate() would-run"), lines);
    }

    @Test
    void buildsClientsWhenNotADryRun() {
        TestServerClientCache<String> clients = new TestServerClientCache<>(URI::toString);
        assertEquals(ENDPOINT.toString(), clients.forEndpoint(ENDPOINT));
    }

    /** Run only by the launcher above; the Gradle test task excludes the tag. */
    @Tag("feature-gate-log-fixture")
    static class Fixture {

        @Test
        void gatedThenClient() {
            FeatureGate.require(Set.of("raw-aes"), FeatureGateLogTest.RUST, FeatureGateLogTest.DECLARATIONS);
            CLIENTS.forEndpoint(ENDPOINT);
        }

        @Test
        void skippedByGate() {
            FeatureGate.require(Set.of("caching"), FeatureGateLogTest.RUST, FeatureGateLogTest.DECLARATIONS);
            CLIENTS.forEndpoint(ENDPOINT);
        }

        @Test
        void clientInsideAssertThrows() {
            assertThrows(IllegalStateException.class, () -> CLIENTS.forEndpoint(ENDPOINT));
        }

        @Test
        void noGate() {
            CLIENTS.forEndpoint(ENDPOINT);
        }
    }
}
