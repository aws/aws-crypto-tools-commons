package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSetLoader;
import aws.cryptography.esdk.testserver.orchestrator.launch.JavaServerLauncher;
import aws.cryptography.esdk.testserver.orchestrator.report.Result;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.GradleTestRunner;
import aws.cryptography.esdk.testserver.orchestrator.source.Override;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Runnable entrypoint for the ESDK TestServer orchestrator closure. Wires the
 * real Java launch path (in-process Netty server on the configured port) and the
 * real Gradle {@code Tests} run, then prints the fail-open {@link Result} and
 * exits non-zero on failure.
 *
 * <p>Configuration and paths:
 * <ul>
 *   <li>{@code -Desdk.testserver.config=<path>} — the Configuration_Set JSON
 *       (default {@code config/configuration-set.json} relative to the working
 *       directory, which is the orchestrator module when launched via Gradle).</li>
 *   <li>{@code -Desdk.testserver.root=<path>} — the ESDK TestServer directory
 *       root used for duplicate-Tests detection and to locate the {@code tests}
 *       module (default: the parent of the working directory).</li>
 * </ul>
 *
 * <p>Overrides are supplied as arguments of the form
 * {@code <mode>:<language>=<value>}, e.g. {@code live:java=/abs/path},
 * {@code submodule:python=<commit>}, {@code artifact:go=<version>}.
 */
public final class ESDKTestServerMain {

    private ESDKTestServerMain() {
    }

    public static void main(String[] args) {
        Path workingDir = Path.of("").toAbsolutePath();
        Path configPath = Path.of(System.getProperty(
            "esdk.testserver.config", workingDir.resolve("config/configuration-set.json").toString()));
        Path testServerRoot = Path.of(System.getProperty(
            "esdk.testserver.root",
            workingDir.getParent() != null ? workingDir.getParent().toString() : workingDir.toString()));
        Path testsModuleDir = testServerRoot.resolve("tests");

        List<Override> overrides = parseOverrides(args);

        ConfigurationSet set = ConfigurationSetLoader.load(configPath);

        ESDKTestServer orchestrator = new ESDKTestServer(
            set,
            new JavaServerLauncher(),
            new GradleTestRunner(testsModuleDir),
            new DuplicateTestsDetector(),
            testServerRoot);

        System.out.println("==> ESDKTestServer run");
        System.out.println("    config: " + configPath);
        System.out.println("    testServerRoot: " + testServerRoot);
        System.out.println("    overrides: " + overrides);

        Result result = orchestrator.run(overrides);

        System.out.println();
        System.out.println("==> Result: " + (result.succeeded() ? "SUCCESS" : "FAILURE"));
        System.out.println("    " + result.summary());
        for (String detail : result.details()) {
            System.out.println("      - " + detail);
        }

        System.exit(result.succeeded() ? 0 : 1);
    }

    static List<Override> parseOverrides(String[] args) {
        List<Override> overrides = new ArrayList<>();
        if (args == null) {
            return overrides;
        }
        for (String arg : args) {
            if (arg == null || arg.isBlank()) {
                continue;
            }
            int colon = arg.indexOf(':');
            int equals = arg.indexOf('=');
            if (colon < 0 || equals < 0 || equals < colon) {
                throw new IllegalArgumentException(
                    "invalid override '" + arg + "'; expected <mode>:<language>=<value>");
            }
            String mode = arg.substring(0, colon).trim().toLowerCase();
            String language = arg.substring(colon + 1, equals).trim();
            String value = arg.substring(equals + 1).trim();
            overrides.add(switch (mode) {
                case "live" -> new Override.Live(language, Path.of(value));
                case "submodule" -> new Override.Submodule(language, value);
                case "artifact" -> new Override.Artifact(language, value);
                default -> throw new IllegalArgumentException(
                    "unknown override mode '" + mode + "' in '" + arg + "'");
            });
        }
        return overrides;
    }
}
