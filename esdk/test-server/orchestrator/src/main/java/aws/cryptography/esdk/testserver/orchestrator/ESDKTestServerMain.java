package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationLoadException;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationLoader;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.launch.CLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.CppShimLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.DotnetLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.GoLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.JavaLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.LauncherFactory;
import aws.cryptography.esdk.testserver.orchestrator.launch.NodeLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.PythonLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.launch.RustLaunchPlan;
import aws.cryptography.esdk.testserver.orchestrator.report.Result;
import aws.cryptography.esdk.testserver.orchestrator.run.DuplicateTestsDetector;
import aws.cryptography.esdk.testserver.orchestrator.run.GradleTestRunner;
import aws.cryptography.esdk.testserver.orchestrator.source.CommonsOrigin;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.esdk.testserver.orchestrator.source.RunContext;
import aws.cryptography.esdk.testserver.orchestrator.source.SourceMaterializer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Runnable entrypoint for the ESDK TestServer orchestrator core (task 9.1). It
 * parses the execution-context CLI, wires the real pipeline — git source
 * materialization ({@link SourceMaterializer}), the per-language subprocess
 * launch plans ({@link JavaLaunchPlan} / {@link PythonLaunchPlan}; every
 * {@code Language_Server} is built and launched as a subprocess from its
 * resolved source directory, Requirements 1.5, 2.7), and the real Gradle
 * {@code Tests} run — then prints the fail-open {@link Result} and
 * <b>exits non-zero on any failed result</b> (design "Error Handling"; the CI
 * failure semantics of Requirements 6.4/6.8 ride on this exit code).
 *
 * <h2>Context CLI</h2>
 * <p>Arguments are {@code key=value} tokens (order-independent):
 * <ul>
 *   <li>{@code context=commons} (default) — a {@code Commons_Run} from the
 *       enclosing commons working tree: every language resolves from the
 *       Configuration_Entry values stored in this tree (Requirement 4.1).</li>
 *   <li>{@code context=language:<lang>} — a {@code Language_Repository_Run} for
 *       {@code <lang>}: its working tree is the source for {@code <lang>}'s
 *       library and server (Requirement 4.2) and every Other language resolves
 *       from the commons clone this core runs inside (Requirement 4.3). Requires
 *       {@code languageRepoRoot=<abs path>} and the {@code commonsOrigin.*}
 *       coordinates.</li>
 *   <li>{@code languageRepoRoot=<abs path>} — the Language_Repository working
 *       tree root (LANGUAGE runs).</li>
 *   <li>{@code commonsOrigin.url=<url>}, {@code commonsOrigin.branch=<branch>},
 *       {@code commonsOrigin.reason=<configuration-entry|invocation-override>}
 *       — the coordinates the commons clone was obtained at and why (the
 *       Commons_Configuration_Entry branch by default, or an invocation-time
 *       branch override; Requirements 4.5, 4.8). The bootstrap Makefile
 *       (task 11.2) supplies these; {@code reason} defaults to
 *       {@code configuration-entry}.</li>
 *   <li>{@code invokingRepositoryName=<name>} — optional override of the
 *       canonical name of the repository the invocation runs from (matched
 *       against Server_Location repositories for the working-tree rule,
 *       Requirement 3.4). Defaults to {@code aws-crypto-tools-commons} for a
 *       Commons_Run and {@code aws-crypto-tools-<lang>} for a
 *       Language_Repository_Run.</li>
 *   <li>{@code referenceImplementation=<lang>} — the language whose
 *       Language_Server plays the immaterial side of single-sided Tests
 *       (default {@code java}). Must name a configured language; an unknown
 *       value aborts the run listing the valid languages. Handed to the Tests
 *       as {@code esdk.testserver.referenceImplementation}.</li>
 * </ul>
 *
 * <h2>Paths (JVM system properties)</h2>
 * <ul>
 *   <li>{@code -Desdk.testserver.root=<path>} — the ESDK TestServer directory
 *       root used for duplicate-Tests detection and to locate the {@code tests}
 *       module and the Configuration_Set (default: the parent of the working
 *       directory, which is the orchestrator module when launched via
 *       Gradle).</li>
 *   <li>{@code -Desdk.testserver.config=<path>} — the Configuration_Set JSON
 *       (default {@code config/ directory} under the TestServer
 *       root — the Configuration_Set's TestServer-level home).</li>
 * </ul>
 *
 * <p>Launch-plan scratch space (clones, venvs, server logs) lives under
 * {@code orchestrator/build/} so a {@code gradlew clean} resets it.
 */
public final class ESDKTestServerMain {

    /** Canonical name of the commons repository. */
    static final String COMMONS_REPOSITORY_NAME = "aws-crypto-tools-commons";

    /** Exit code for a malformed invocation (bad CLI), distinct from a failed run (1). */
    private static final int EXIT_USAGE = 2;

    private ESDKTestServerMain() {
    }

    public static void main(String[] args) {
        Map<String, String> cli;
        try {
            cli = parseArgs(args);
        } catch (IllegalArgumentException e) {
            System.err.println("ESDKTestServer: " + e.getMessage());
            System.err.println(usage());
            System.exit(EXIT_USAGE);
            return;
        }

        Path workingDir = Path.of("").toAbsolutePath();
        Path testServerRoot = Path.of(System.getProperty(
            "esdk.testserver.root",
            workingDir.getParent() != null ? workingDir.getParent().toString() : workingDir.toString()));
        Path configPath = Path.of(System.getProperty(
            "esdk.testserver.config",
            testServerRoot.resolve("config").toString()));
        Path testsModuleDir = testServerRoot.resolve("tests");

        // The commons checkout the run reads shared components from: the working
        // tree for a Commons_Run, the clone this core runs inside for a
        // Language_Repository_Run (both are <commonsRoot>/esdk/test-server).
        Path commonsRoot = commonsRootFrom(testServerRoot);

        // Launch-plan scratch space under orchestrator/build/ (clones, venvs,
        // server logs); the model dir is the commons-hosted Smithy_Model
        // (Requirement 1.7).
        Path orchestratorBuildDir = testServerRoot.resolve("orchestrator/build");
        Path modelDir = testServerRoot.resolve("model");

        // Build the execution context from the CLI, and (for a language run)
        // load the invoking repository's Configuration_Overrides. The
        // Configuration_Set is loaded first: the overrides live in the own
        // language's commons-configuration file, whose repository-root-relative
        // location the own Configuration_Entry may override via
        // commonsConfigurationPath.
        ConfigurationSet set = ConfigurationLoader.loadConfigurationSet(configPath);
        RunContext context;
        List<ConfigurationEntry> overrides;
        try {
            String contextArg = cli.getOrDefault("context", "commons");
            if ("commons".equals(contextArg)) {
                String invoking = cli.getOrDefault("invokingRepositoryName", COMMONS_REPOSITORY_NAME);
                context = RunContext.commonsRun(commonsRoot, invoking);
                overrides = List.of();
            } else if (contextArg.startsWith("language:")) {
                String ownLanguage = contextArg.substring("language:".length()).trim();
                if (ownLanguage.isEmpty()) {
                    throw new IllegalArgumentException(
                        "context=language:<lang> requires a non-empty language");
                }
                Path languageRepoRoot = requiredPath(cli, "languageRepoRoot");
                CommonsOrigin origin = commonsOriginFrom(cli);
                String invoking = cli.getOrDefault(
                    "invokingRepositoryName", "aws-crypto-tools-" + ownLanguage);
                context = RunContext.languageRun(
                    ownLanguage, languageRepoRoot, commonsRoot, invoking, origin);
                overrides = loadOverrides(languageRepoRoot, set.forLanguage(ownLanguage));
            } else {
                throw new IllegalArgumentException(
                    "unknown context '" + contextArg
                        + "' (expected 'commons' or 'language:<lang>')");
            }
        } catch (IllegalArgumentException e) {
            System.err.println("ESDKTestServer: " + e.getMessage());
            System.err.println(usage());
            System.exit(EXIT_USAGE);
            return;
        }

        // Per-language subprocess launch plans (Requirements 1.5, 2.7): a
        // language absent from this map aborts the run naming the language.
        // rust-dafny reuses RustLaunchPlan: its server is the same cargo
        // build/launch shape, delegating to the Dafny-generated aws-esdk crate.
        LauncherFactory launchers = LauncherFactory.fromMap(Map.of(
            "java", (Launcher) new JavaLaunchPlan(
                orchestratorBuildDir.resolve("launch/java"), modelDir),
            "python", new PythonLaunchPlan(
                orchestratorBuildDir.resolve("launch/python")),
            "rust", new RustLaunchPlan(
                orchestratorBuildDir.resolve("launch/rust")),
            "rust-cpp", new CppShimLaunchPlan(
                orchestratorBuildDir.resolve("launch/rust-cpp")),
            "javascript", new NodeLaunchPlan(
                orchestratorBuildDir.resolve("launch/javascript")),
            "c", new CLaunchPlan(
                orchestratorBuildDir.resolve("launch/c")),
            "net", new DotnetLaunchPlan(
                orchestratorBuildDir.resolve("launch/net")),
            "rust-dafny", new RustLaunchPlan(
                orchestratorBuildDir.resolve("launch/rust-dafny")),
            "go", new GoLaunchPlan(
                orchestratorBuildDir.resolve("launch/go"))));

        // The reference implementation for single-sided Tests: the
        // referenceImplementation=<lang> argument, defaulting to java. The
        // pipeline validates it against the Configuration_Set's languages and
        // aborts on an unknown value.
        String referenceImplementation = cli.getOrDefault(
            "referenceImplementation", ESDKTestServer.DEFAULT_REFERENCE_IMPLEMENTATION);

        ESDKTestServer orchestrator = new ESDKTestServer(
            set,
            context,
            new SourceMaterializer(orchestratorBuildDir.resolve("sources")),
            launchers,
            new GradleTestRunner(testsModuleDir),
            new DuplicateTestsDetector(),
            testServerRoot,
            referenceImplementation);

        System.out.println("==> ESDKTestServer run");
        System.out.println("    context: " + describeContext(context));
        System.out.println("    config: " + configPath);
        System.out.println("    testServerRoot: " + testServerRoot);
        System.out.println("    commonsRoot: " + commonsRoot);
        System.out.println("    referenceImplementation: " + referenceImplementation);
        if (context.kind() == RunContext.Kind.LANGUAGE) {
            System.out.println("    languageRepoRoot: " + context.languageRepoRoot());
            CommonsOrigin origin = context.commonsOrigin();
            System.out.println("    commonsOrigin: " + origin.url()
                + " @ " + origin.branch() + " (" + origin.reason().label() + ")");
            System.out.println("    configurationOverrides: " + overrides.size());
        }

        // Dev-only local-overrides overlay (local development, gitignored): map a
        // language to a local working-tree root the resolver uses instead of a
        // clone. Default location config/local-overrides.json; point elsewhere
        // with localOverrides=<path>. Absent → no overlay (normal run).
        Path localOverridesFile = cli.containsKey("localOverrides")
            ? Path.of(cli.get("localOverrides"))
            : configPath.resolve("local-overrides.json");
        Map<String, Path> localRepositories = Map.of();
        if (Files.isRegularFile(localOverridesFile)) {
            try {
                localRepositories = ConfigurationLoader.loadLocalRepositories(localOverridesFile);
            } catch (ConfigurationLoadException e) {
                System.err.println("ESDKTestServer: " + e.getMessage());
                System.exit(EXIT_USAGE);
                return;
            }
            if (!localRepositories.isEmpty()) {
                System.out.println("    localOverrides: " + localOverridesFile);
                localRepositories.forEach((lang, root) ->
                    System.out.println("      " + lang + " -> " + root + " (local working tree)"));
            }
        }

        Result result = orchestrator.run(overrides, localRepositories);

        System.out.println();
        System.out.println("==> Result: " + (result.succeeded() ? "SUCCESS" : "FAILURE"));
        System.out.println("    " + result.summary());
        for (String detail : result.details()) {
            System.out.println("      - " + detail);
        }

        // Exit non-zero on any failed result (CI failure semantics, Req 6.4/6.8).
        System.exit(result.succeeded() ? 0 : 1);
    }

    // ------------------------------------------------------------------
    // CLI parsing
    // ------------------------------------------------------------------

    /** Parse {@code key=value} tokens; a token without {@code '='} is an error. */
    static Map<String, String> parseArgs(String[] args) {
        Map<String, String> parsed = new java.util.LinkedHashMap<>();
        for (String arg : args) {
            if (arg == null || arg.isBlank()) {
                continue;
            }
            int eq = arg.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException(
                    "argument '" + arg + "' is not a key=value token");
            }
            parsed.put(arg.substring(0, eq).trim(), arg.substring(eq + 1).trim());
        }
        return parsed;
    }

    /**
     * The {@link CommonsOrigin} for a Language_Repository_Run from the
     * {@code commonsOrigin.*} CLI tokens: {@code url} and {@code branch} are
     * required; {@code reason} defaults to {@code configuration-entry}
     * (Requirements 4.5, 4.8).
     */
    private static CommonsOrigin commonsOriginFrom(Map<String, String> cli) {
        String url = required(cli, "commonsOrigin.url");
        String branch = required(cli, "commonsOrigin.branch");
        String reasonLabel = cli.getOrDefault(
            "commonsOrigin.reason", ResolutionReason.CONFIGURATION_ENTRY.label());
        ResolutionReason reason = reasonFromLabel(reasonLabel);
        return new CommonsOrigin(url, branch, reason);
    }

    /** Only the two branch-selection reasons are valid for {@code commonsOrigin.reason}. */
    private static ResolutionReason reasonFromLabel(String label) {
        if (ResolutionReason.CONFIGURATION_ENTRY.label().equals(label)) {
            return ResolutionReason.CONFIGURATION_ENTRY;
        }
        if (ResolutionReason.INVOCATION_OVERRIDE.label().equals(label)) {
            return ResolutionReason.INVOCATION_OVERRIDE;
        }
        throw new IllegalArgumentException(
            "commonsOrigin.reason must be '" + ResolutionReason.CONFIGURATION_ENTRY.label()
                + "' or '" + ResolutionReason.INVOCATION_OVERRIDE.label()
                + "' (was '" + label + "')");
    }

    /**
     * Load the invoking Language_Repository's Configuration_Overrides from its
     * commons-configuration file (Requirement 4.6), at the location the own
     * language's Configuration_Entry declares ({@code commonsConfigurationPath},
     * defaulting to the standard location). A missing/unparseable file halts the
     * invocation before any run — the same failure the bootstrap reports
     * (Requirement 4.9) — surfaced here as a usage error.
     */
    private static List<ConfigurationEntry> loadOverrides(
            Path languageRepoRoot, ConfigurationEntry ownEntry) {
        Path expected = languageRepoRoot.resolve(
            ESDKTestServer.configDirectory(ownEntry));
        try {
            CommonsConfiguration own = ConfigurationLoader.loadCommonsConfiguration(expected);
            return own.configurationOverrides();
        } catch (ConfigurationLoadException e) {
            throw new IllegalArgumentException(
                "could not read the server config at " + expected
                    + ": " + e.getMessage());
        }
    }

    private static Path requiredPath(Map<String, String> cli, String key) {
        return Path.of(required(cli, key)).toAbsolutePath();
    }

    private static String required(Map<String, String> cli, String key) {
        String value = cli.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing required argument '" + key + "'");
        }
        return value;
    }

    private static String describeContext(RunContext context) {
        return context.kind() == RunContext.Kind.COMMONS
            ? "commons (" + context.invokingRepositoryName() + ")"
            : "language:" + context.ownLanguage()
                + " (" + context.invokingRepositoryName() + ")";
    }

    private static String usage() {
        return "usage: run context=commons"
            + " | context=language:<lang> languageRepoRoot=<abs path>"
            + " commonsOrigin.url=<url> commonsOrigin.branch=<branch>"
            + " [commonsOrigin.reason=configuration-entry|invocation-override]"
            + " [invokingRepositoryName=<name>]"
            + " [referenceImplementation=<lang>]";
    }

    /**
     * Derive the commons repository root from the TestServer root
     * ({@code <commonsRoot>/esdk/test-server}), falling back to the TestServer
     * root itself if the expected layout is not present.
     */
    static Path commonsRootFrom(Path testServerRoot) {
        Path esdkDir = testServerRoot.getParent();
        if (esdkDir != null && esdkDir.getParent() != null) {
            return esdkDir.getParent();
        }
        return testServerRoot;
    }
}
