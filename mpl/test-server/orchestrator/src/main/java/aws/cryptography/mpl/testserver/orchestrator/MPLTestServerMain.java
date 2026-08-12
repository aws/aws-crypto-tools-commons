package aws.cryptography.mpl.testserver.orchestrator;

import aws.cryptography.mpl.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.mpl.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.mpl.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.mpl.testserver.orchestrator.launch.RustLaunchPlan;
import aws.cryptography.mpl.testserver.orchestrator.run.GradleTestRunner;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Orchestrator entrypoint for the MPL TestServer.
 *
 * <p>CLI: {@code context=language:rust languageRepoRoot=<path>}
 */
public final class MPLTestServerMain {

    private MPLTestServerMain() {
    }

    public static void main(String[] args) {
        Map<String, String> cli = parseArgs(args);

        Path workingDir = Path.of("").toAbsolutePath();
        Path testServerRoot = workingDir.getParent() != null ? workingDir.getParent() : workingDir;
        Path configPath = testServerRoot.resolve("config/configuration-set.json");
        Path testsModuleDir = testServerRoot.resolve("tests");

        ConfigurationSet config;
        try {
            config = new ObjectMapper().readValue(configPath.toFile(), ConfigurationSet.class);
        } catch (IOException e) {
            System.err.println("Failed to load configuration: " + e.getMessage());
            System.exit(2);
            return;
        }

        System.out.println("==> MPLTestServer orchestrator");
        System.out.println("    product: " + config.product());
        System.out.println("    features: " + config.features());
        System.out.println("    languages: " + config.entries().size());

        String contextArg = cli.getOrDefault("context", "commons");
        Path languageRepoRoot = null;
        if (contextArg.startsWith("language:")) {
            String repoRootStr = cli.get("languageRepoRoot");
            if (repoRootStr == null) {
                System.err.println("languageRepoRoot is required for context=language:*");
                System.exit(2);
                return;
            }
            languageRepoRoot = Path.of(repoRootStr);
        }

        List<LaunchedServer> servers = new ArrayList<>();
        try {
            for (ConfigurationEntry entry : config.entries()) {
                System.out.println("    launching " + entry.language() + " on port " + entry.port());
                Path serverDir = resolveServerDir(entry, languageRepoRoot, contextArg);
                RustLaunchPlan plan = new RustLaunchPlan(serverDir);
                LaunchedServer server = plan.launch(entry.port());
                servers.add(server);
                System.out.println("    " + entry.language() + " ready");
            }

            String targets = config.entries().stream()
                .map(e -> e.language() + ":" + e.majorVersion() + "=http://127.0.0.1:" + e.port())
                .collect(Collectors.joining(","));

            System.out.println("==> Running tests");
            int exitCode = GradleTestRunner.run(testsModuleDir, Map.of(
                "mpl.testserver.targets", targets,
                "mpl.testserver.featureCatalog", String.join(",", config.features())
            ));

            System.out.println("==> Result: " + (exitCode == 0 ? "SUCCESS" : "FAILURE"));
            System.exit(exitCode);

        } finally {
            for (LaunchedServer server : servers) {
                server.stop();
            }
        }
    }

    private static Path resolveServerDir(ConfigurationEntry entry, Path languageRepoRoot, String context) {
        if (context.startsWith("language:") && languageRepoRoot != null) {
            return languageRepoRoot.resolve(entry.serverPath());
        }
        throw new UnsupportedOperationException(
            "Commons_Run source resolution not yet implemented; use context=language:<lang>");
    }

    private static Map<String, String> parseArgs(String[] args) {
        return java.util.Arrays.stream(args)
            .filter(a -> a.contains("="))
            .collect(Collectors.toMap(
                a -> a.substring(0, a.indexOf('=')),
                a -> a.substring(a.indexOf('=') + 1)));
    }
}
