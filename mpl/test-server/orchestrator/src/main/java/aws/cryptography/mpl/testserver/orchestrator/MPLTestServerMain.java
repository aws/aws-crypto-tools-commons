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
        int exitCode;
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
            exitCode = GradleTestRunner.run(testsModuleDir, Map.of(
                "mpl.testserver.targets", targets,
                "mpl.testserver.featureCatalog", String.join(",", config.features())
            ));

            System.out.println("==> Result: " + (exitCode == 0 ? "SUCCESS" : "FAILURE"));

        } finally {
            for (LaunchedServer server : servers) {
                server.stop();
            }
        }

        // Exit AFTER the finally block has torn every server down: System.exit
        // starts JVM shutdown immediately and finally blocks do not run, so
        // exiting inside the try above would leak every launched subprocess.
        System.exit(exitCode);
    }

    private static Path resolveServerDir(ConfigurationEntry entry, Path languageRepoRoot, String context) {
        if (context.startsWith("language:") && languageRepoRoot != null) {
            return languageRepoRoot.resolve(entry.serverPath());
        }
        // Commons_Run: git-clone the server repo at the configured ref
        if (entry.serverLocation() == null) {
            throw new RuntimeException("No serverLocation configured for " + entry.language());
        }
        String url = entry.serverLocation().url();
        String ref = entry.serverLocation().ref();
        String path = entry.serverLocation().path();

        Path cloneDir = Path.of(System.getProperty("java.io.tmpdir"))
            .resolve("mpl-testserver-clones")
            .resolve(entry.language());

        System.out.println("    cloning " + url + " @ " + ref + " into " + cloneDir);

        try {
            if (cloneDir.toFile().exists()) {
                new ProcessBuilder("rm", "-rf", cloneDir.toString())
                    .inheritIO().start().waitFor();
            }
            int exitCode = new ProcessBuilder(
                "git", "clone", "--depth", "1", "--single-branch", "--branch", ref, url, cloneDir.toString())
                .inheritIO().start().waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("git clone failed with exit code " + exitCode
                    + " for " + url + " @ " + ref);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to clone " + url + " @ " + ref, e);
        }

        return cloneDir.resolve(path);
    }

    private static Map<String, String> parseArgs(String[] args) {
        return java.util.Arrays.stream(args)
            .filter(a -> a.contains("="))
            .collect(Collectors.toMap(
                a -> a.substring(0, a.indexOf('=')),
                a -> a.substring(a.indexOf('=') + 1)));
    }
}
