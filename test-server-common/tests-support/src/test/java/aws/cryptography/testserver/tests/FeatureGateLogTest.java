package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

/**
 * Runs {@link Fixture} through a real launcher with concurrent execution and
 * checks that each gate call is logged against the test that made it.
 */
class FeatureGateLogTest {

    private static final String REPO = "dbe";
    static final LanguageServerTarget RUST = target("rust");
    static final LanguageServerTarget JAVA = target("java");
    static final FeatureDeclarations DECLARATIONS = FeatureDeclarations.parse(
        "rust:1:" + REPO + ":raw-aes=true;caching=false,java:1:" + REPO + ":raw-aes=true;caching=true",
        "raw-aes,caching");

    private static LanguageServerTarget target(String language) {
        return new LanguageServerTarget(language, 1, REPO, URI.create("http://localhost:1"));
    }

    @Test
    void logsEveryGateCallAgainstItsTest(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("gate.jsonl");
        System.setProperty(FeatureGateLog.PATH_PROPERTY, log.toString());
        try {
            LauncherFactory.create().execute(LauncherDiscoveryRequestBuilder.request()
                .selectors(selectClass(Fixture.class))
                .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
                .configurationParameter("junit.jupiter.execution.parallel.mode.default", "concurrent")
                .build());
        } finally {
            System.clearProperty(FeatureGateLog.PATH_PROPERTY);
        }

        ObjectMapper json = new ObjectMapper();
        Set<String> lines = new TreeSet<>();
        for (String line : Files.readAllLines(log)) {
            Map<?, ?> m = json.readValue(line, Map.class);
            lines.add(m.get("name") + " " + m.get("targets") + " " + m.get("features") + " " + m.get("result"));
        }
        Set<String> expected = new TreeSet<>();
        expected.add("pairGatesEachSide() [rust-v1] [raw-aes] run");
        expected.add("pairGatesEachSide() [java-v1] [caching, raw-aes] run");
        expected.add("unsupportedIsSkipped() [rust-v1] [caching] skipped");
        IntStream.range(0, 20).forEach(i -> {
            expected.add("param " + i + " [java-v1, rust-v1] [raw-aes] run");
            expected.add("dynamic " + i + " [rust-v1] [raw-aes] run");
        });
        assertEquals(expected, lines);
    }

    /** Run only by the launcher above; the Gradle test task excludes the tag. */
    @Tag("feature-gate-log-fixture")
    static class Fixture {

        @Test
        void pairGatesEachSide() {
            FeatureGate.require(Set.of("raw-aes"), RUST, DECLARATIONS);
            FeatureGate.require(Set.of("raw-aes", "caching"), JAVA, DECLARATIONS);
        }

        @Test
        void unsupportedIsSkipped() {
            FeatureGate.require(Set.of("caching"), RUST, DECLARATIONS);
        }

        @ParameterizedTest(name = "param {0}")
        @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19})
        void param(int i) {
            FeatureGate.require(Set.of("raw-aes"), new TargetPair(JAVA, RUST), DECLARATIONS);
        }

        @TestFactory
        Stream<DynamicTest> dynamic() {
            return IntStream.range(0, 20).mapToObj(i -> DynamicTest.dynamicTest("dynamic " + i,
                () -> FeatureGate.require(Set.of("raw-aes"), RUST, DECLARATIONS)));
        }
    }
}
