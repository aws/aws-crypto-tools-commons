package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Java {@code Language_Server} launch plan (task 6.2, Requirements 1.7,
 * 2.1). Absorbs the aws-database-encryption-sdk-dynamodb Makefile's {@code build-live-esdk}
 * flow and the commons server's {@code runServer} launch, driven from the
 * run's <em>resolved</em> sources:
 *
 * <ol>
 *   <li><b>Resolve.</b> The Java library directory (the resolved live ESDK
 *       Java source, working tree or clone) and the Java server directory
 *       come from the {@link MaterializedSources}; a missing component is a
 *       {@code RESOLVE} launch failure (Requirement 2.5).</li>
 *   <li><b>Stamp-and-install ({@code build-live-esdk}), when the resolved
 *       library carries its own Maven build.</b> Only runs when the resolved
 *       library directory has a {@code pom.xml} at its root — an SDK whose
 *       Language_Server consumes the library from a published Maven Central
 *       artifact (e.g. the DBE Java server, which resolves the library from
 *       Maven Central via {@code gradle.properties} rather than a live source
 *       build) has no {@code pom.xml} there and this step is skipped
 *       entirely, no {@code -PesdkVersion} is passed to the launch. When it
 *       does run: the resolved library is installed to the local Maven
 *       repository under a distinct version
 *       ({@code 0.0.0-testserver-<timestamp>}) so the server build provably
 *       consumes THIS resolved build via {@code mavenLocal()} +
 *       {@code -PesdkVersion} rather than the published GA artifact:
 *       {@code mvn versions:set} (backup poms kept) → {@code mvn install}
 *       (tests, javadoc, and jacoco skipped — this produces a build artifact,
 *       it does not gate the ESDK's own suite) → {@code mvn versions:revert},
 *       which ALWAYS runs (in a {@code finally}, best-effort like the
 *       Makefile's {@code || true}) so the resolved tree is never left
 *       stamped. The Maven {@code JAVA_HOME} is resolved eagerly regardless
 *       of whether mvn actually runs (a JDK 17-class home; the live ESDK
 *       build targets Java 8 and builds on JDK 8/11/17), mirroring the
 *       Makefile's resolution: an explicit home wins, else macOS
 *       {@code /usr/libexec/java_home -v 17/11/1.8}, else the ambient
 *       environment (mvn on PATH as-is). An explicit home without an
 *       executable {@code bin/java} is a {@code BUILD} failure naming the
 *       cause, before any Maven step runs. Any failing Maven step is a
 *       {@code BUILD} launch failure naming the step and carrying the tool
 *       output.</li>
 *   <li><b>Transpile-and-publish, when the resolved library is a smithy-dafny
 *       {@code runtimes/java} directory</b> ({@link DafnyProject}): in the
 *       clone root, {@code git submodule update --init --recursive} each
 *       present Dafny submodule, then {@code make build_java mvn_local_deploy}
 *       in the library's project directory under the Maven {@code JAVA_HOME},
 *       so the server resolves this build from {@code mavenLocal()}. Dafny
 *       must be on {@code PATH}.</li>
 *   <li><b>Launch.</b> {@code ./gradlew runServer --args=<port>
 *       [-PesdkVersion=<stamped>] -PmodelDir=<commons model dir>} in the
 *       resolved server directory under a JDK 21+ {@code JAVA_HOME}
 *       (smithy-java baselines on 21; resolution mirrors the Makefile's
 *       {@code HARNESS_JAVA_HOME}: explicit home wins, else
 *       {@code java_home -v 23/22/21}, else ambient), via the shared
 *       {@link SubprocessLauncher} (port probe, TCP readiness, process-tree
 *       teardown). The {@code -PmodelDir} property is harmless extra while
 *       the commons server build still uses its relative model path, and
 *       required once the relocated server (task 12.1) demands it.</li>
 * </ol>
 *
 * <p>Command construction is pure ({@code static} builders) so the exact
 * subprocess invocations are unit-testable without running a real Maven or
 * Gradle build; the end-to-end launch is exercised by the orchestrated run
 * (checkpoint 10).
 */
public final class JavaLaunchPlan implements Launcher {

    /** The distinct-version prefix stamped onto the resolved library. */
    static final String STAMP_PREFIX = "0.0.0-testserver-";

    /** Maven from PATH, exactly as the Makefile's {@code build-live-esdk} invokes it. */
    static final String MVN = "mvn";

    /**
     * A Dafny library's stamp is {@code .java-library-build-stamp} in its
     * smithy-dafny project directory, recording the library commit the local
     * Maven install was built from.
     */
    static final String DAFNY_LIBRARY_STAMP = "java-library";

    private static final DateTimeFormatter STAMP_TIMESTAMP =
        DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

    private static final String SERVER_LOG_NAME = "java-server.log";
    private static final String MAC_JAVA_HOME_TOOL = "/usr/libexec/java_home";

    /** JDK majors acceptable for the live ESDK Maven build (Makefile's ESDK_JAVA_HOME). */
    private static final String[] ESDK_JDK_VERSIONS = {"17", "11", "1.8"};

    /** JDK majors acceptable for the smithy-java server (Makefile's HARNESS_JAVA_HOME). */
    private static final String[] HARNESS_JDK_VERSIONS = {"23", "22", "21"};

    /** Cap on the tool output carried in a BUILD failure message. */
    private static final int MAX_FAILURE_OUTPUT_CHARS = 4000;

    private final Path workDirectory;
    private final Path modelDir;
    private final Path esdkJavaHome;
    private final Path harnessJavaHome;
    private final SubprocessLauncher subprocessLauncher;

    /**
     * @param workDirectory scratch directory owned by this plan; hosts the
     *                      server log
     * @param modelDir      the commons Smithy model directory
     *                      ({@code <commonsRoot>/dbesdk/test-server/model}),
     *                      passed to the server build as {@code -PmodelDir}
     */
    public JavaLaunchPlan(Path workDirectory, Path modelDir) {
        this(workDirectory, modelDir, null, null, new SubprocessLauncher());
    }

    /**
     * @param workDirectory      scratch directory owned by this plan
     * @param modelDir           the commons Smithy model directory, passed to
     *                           the server build as {@code -PmodelDir}
     * @param esdkJavaHome       JDK 17-class home for the live ESDK Maven
     *                           build, or {@code null} to resolve like the
     *                           Makefile ({@code java_home -v 17/11/1.8},
     *                           else the ambient environment)
     * @param harnessJavaHome    JDK 21+ home for the smithy-java server
     *                           launch, or {@code null} to resolve like the
     *                           Makefile ({@code java_home -v 23/22/21},
     *                           else the ambient environment)
     * @param subprocessLauncher the shared launch machinery (injectable
     *                           readiness timeout for tests)
     */
    public JavaLaunchPlan(Path workDirectory, Path modelDir, Path esdkJavaHome,
            Path harnessJavaHome, SubprocessLauncher subprocessLauncher) {
        if (workDirectory == null) {
            throw new IllegalArgumentException("workDirectory is required");
        }
        if (modelDir == null) {
            throw new IllegalArgumentException("modelDir is required");
        }
        if (subprocessLauncher == null) {
            throw new IllegalArgumentException("subprocessLauncher is required");
        }
        this.workDirectory = workDirectory;
        this.modelDir = modelDir;
        this.esdkJavaHome = esdkJavaHome;
        this.harnessJavaHome = harnessJavaHome;
        this.subprocessLauncher = subprocessLauncher;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        String language = entry.language();

        // 1. Resolve the materialized library + server directories (Req 2.5).
        Path libraryDir = sources.directoryOf(ComponentId.library(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.library(language)));
        Path serverDir = sources.directoryOf(ComponentId.server(language))
            .orElseThrow(() -> missingComponent(language, ComponentId.server(language)));

        try {
            Files.createDirectories(workDirectory);
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to create the " + language + " launch work directory "
                    + workDirectory + ": " + e.getMessage(), e);
        }

        // 2. Resolve the Maven JAVA_HOME first — an explicitly-set unusable
        //    home is a BUILD failure whether or not the library actually needs
        //    a Maven build. That eager validation preserves the harness
        //    contract (a misconfigured home never reaches the launch step).
        Optional<Path> mavenJavaHome =
            resolveJavaHome(language, "live ESDK Maven build (JDK 17-class)",
                esdkJavaHome, ESDK_JDK_VERSIONS);

        // 3. Stamp-and-install the resolved library (the Makefile's
        //    build-live-esdk) under a distinct version; versions:revert
        //    ALWAYS runs so the tree isn't left stamped. Skipped for SDKs
        //    whose Language_Server consumes its library from a published
        //    Maven Central artifact rather than a live source build —
        //    detected by the absence of a pom.xml at the resolved library
        //    root. In that case the server relies on its own
        //    gradle.properties-default version and never sees -PesdkVersion.
        //    A clean clone is stamped with its commit, and the install is
        //    skipped when that version is already in the local repository.
        String stampedVersion = null;
        Optional<Path> dafnyProject = DafnyProject.of(libraryDir);
        if (dafnyProject.isPresent()) {
            // Skipped when the stamp shows this library commit is already
            // transpiled and published to the local Maven repository (a
            // prebuilt install restored alongside its stamp).
            MaterializedSources.Success library = sources.successOf(ComponentId.library(language))
                .orElseThrow(() -> missingComponent(language, ComponentId.library(language)));
            BuildStamp stamp = new BuildStamp(dafnyProject.get(), DAFNY_LIBRARY_STAMP);
            if (!stamp.upToDate(library.commit(), library.dirty(), List.of())) {
                if (!DafnyProject.commandOnPath("dafny", System.getenv("PATH"))) {
                    throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                        "the " + language + " Language_Server build requires Dafny on PATH ('dafny'"
                            + " was not found): the Java library transpiles from Dafny before building");
                }
                Path repoRoot = DafnyProject.repositoryRoot(dafnyProject.get());
                synchronized (DafnyProject.lockFor(repoRoot)) {
                    for (List<String> submodule : DafnyProject.submoduleCommands(repoRoot)) {
                        runBuildStep(language, String.join(" ", submodule), submodule, repoRoot, mavenJavaHome);
                    }
                    runBuildStep(language, "transpile + publish the library (make build_java mvn_local_deploy)",
                        dafnyBuildCommand(), dafnyProject.get(), mavenJavaHome);
                }
                stamp.write(language, library.commit(), library.dirty());
            }
        } else if (Files.isRegularFile(libraryDir.resolve("pom.xml"))) {
            MaterializedSources.Success library = sources.successOf(ComponentId.library(language))
                .orElseThrow(() -> missingComponent(language, ComponentId.library(language)));
            boolean clean = library.commit() != null && !Boolean.TRUE.equals(library.dirty());
            stampedVersion = clean ? stampVersion(library.commit()) : stampVersion(Instant.now());

            if (!(clean && installedLocally(stampedVersion))) {
                runBuildStep(language, "stamp the live version (mvn versions:set)",
                    versionsSetCommand(stampedVersion), libraryDir, mavenJavaHome);
                try {
                    runBuildStep(language, "install the live library (mvn install)",
                        installCommand(), libraryDir, mavenJavaHome);
                } finally {
                    // Best-effort restore, exactly like the Makefile's
                    // `mvn versions:revert || true`: the resolved tree must never stay
                    // stamped, and a revert hiccup must not mask the install result.
                    revertBestEffort(libraryDir, mavenJavaHome);
                }
            }
        }

        // 3. Launch: ./gradlew runServer --args=<port> -PesdkVersion=<stamped>
        //    -PmodelDir=<commons model dir> in the resolved server directory
        //    under JDK 21+, via the shared probe/spawn/readiness/teardown
        //    machinery.
        Optional<Path> gradleJavaHome =
            resolveJavaHome(language, "smithy-java server launch (JDK 21+)",
                harnessJavaHome, HARNESS_JDK_VERSIONS);
        ProcessBuilder server = new ProcessBuilder(
            serverCommand(serverDir, entry.port(), stampedVersion, modelDir));
        server.directory(serverDir.toFile());
        gradleJavaHome.ifPresent(home ->
            server.environment().put("JAVA_HOME", home.toString()));
        server.redirectErrorStream(true);
        server.redirectOutput(workDirectory.resolve(SERVER_LOG_NAME).toFile());
        return subprocessLauncher.launch(language, entry.port(), server);
    }

    // ------------------------------------------------------------------
    // Pure command construction (unit-testable without Maven/Gradle).
    // ------------------------------------------------------------------

    /**
     * The distinct version stamped onto the resolved library:
     * {@code 0.0.0-testserver-<UTC timestamp>}. A {@code 0.0.0-} version can
     * never collide with a published GA artifact, so the server build's
     * {@code mavenLocal()} lookup provably resolves THIS install.
     */
    static String stampVersion(Instant instant) {
        return STAMP_PREFIX + STAMP_TIMESTAMP.format(instant);
    }

    /** The version stamped onto a clean library clone: {@code 0.0.0-testserver-<commit>}. */
    static String stampVersion(String commit) {
        return STAMP_PREFIX + commit;
    }

    /**
     * Whether {@code ~/.m2/repository} already holds an artifact installed at
     * {@code version}. Stamped versions are unique to one library commit.
     */
    static boolean installedLocally(String version) {
        Path repository = Path.of(System.getProperty("user.home"), ".m2", "repository");
        if (!Files.isDirectory(repository)) {
            return false;
        }
        try (var paths = Files.find(repository, 8,
                (path, attributes) -> attributes.isDirectory()
                    && path.getFileName().toString().equals(version))) {
            return paths.findAny().isPresent();
        } catch (IOException | java.io.UncheckedIOException e) {
            return false;
        }
    }

    /**
     * {@code mvn -q -DnewVersion=<version> versions:set -DgenerateBackupPoms=true}
     * (the Makefile's stamp step; backup poms make {@code versions:revert}
     * possible).
     */
    static List<String> versionsSetCommand(String version) {
        return List.of(MVN, "-q", "-DnewVersion=" + version,
            "versions:set", "-DgenerateBackupPoms=true");
    }

    /**
     * {@code mvn -q -DskipTests -Dmaven.test.skip=true -Djacoco.skip=true
     * -Dmaven.javadoc.skip=true install} — the Makefile's install step: a
     * build artifact is being produced, not the ESDK's own suite gated, so
     * tests, jacoco, and javadoc are all skipped.
     */
    static List<String> installCommand() {
        return List.of(MVN, "-q", "-DskipTests", "-Dmaven.test.skip=true",
            "-Djacoco.skip=true", "-Dmaven.javadoc.skip=true", "install");
    }

    /** {@code mvn -q versions:revert} (the Makefile's restore step). */
    static List<String> versionsRevertCommand() {
        return List.of(MVN, "-q", "versions:revert");
    }

    /** {@code make build_java mvn_local_deploy CORES=4} (the smithy-dafny project directory). */
    static List<String> dafnyBuildCommand() {
        return List.of("make", "build_java", "mvn_local_deploy", "CORES=4");
    }

    /**
     * {@code <serverDir>/gradlew runServer --args=<port>
     * -PesdkVersion=<stamped> -PmodelDir=<modelDir>} — the server's own
     * wrapper, run in the resolved server directory. {@code -PesdkVersion} +
     * {@code mavenLocal()} make the server consume the stamped live install;
     * {@code -PmodelDir} points the (relocated) server build at the commons
     * model directory.
     */
    static List<String> serverCommand(Path serverDir, int port, String stampedVersion,
            Path modelDir) {
        List<String> command = new ArrayList<>();
        command.add(serverDir.resolve("gradlew").toString());
        command.add("runServer");
        command.add("--args=" + port);
        if (stampedVersion != null) {
            command.add("-PesdkVersion=" + stampedVersion);
        }
        command.add("-PmodelDir=" + modelDir);
        return command;
    }

    // ------------------------------------------------------------------
    // JDK home resolution (mirrors the Makefile's ESDK_JAVA_HOME /
    // HARNESS_JAVA_HOME).
    // ------------------------------------------------------------------

    /**
     * Resolve the {@code JAVA_HOME} for one build phase, mirroring the
     * Makefile: an explicit home wins (but must actually contain an
     * executable {@code bin/java} — a {@code BUILD} failure naming the cause
     * otherwise); else the macOS {@code java_home} tool is asked for each
     * acceptable major in order; else empty — the step runs against the
     * ambient environment (the Makefile's "mvn on PATH is then used as-is").
     */
    private static Optional<Path> resolveJavaHome(String language, String purpose,
            Path explicit, String... versions) throws ServerLaunchException {
        if (explicit != null) {
            if (!Files.isExecutable(explicit.resolve("bin").resolve("java"))) {
                throw new ServerLaunchException(language,
                    ServerLaunchException.Category.BUILD,
                    "the configured JAVA_HOME for the " + purpose + " is unusable: "
                        + explicit + " has no executable bin/java");
            }
            return Optional.of(explicit);
        }
        if (Files.isExecutable(Path.of(MAC_JAVA_HOME_TOOL))) {
            for (String version : versions) {
                Optional<Path> candidate = macJavaHome(version);
                if (candidate.isPresent()) {
                    return candidate;
                }
            }
        }
        for (String version : versions) {
            Optional<Path> candidate = setupJavaHome(version, System.getenv());
            if (candidate.isPresent()) {
                return candidate;
            }
        }
        return Optional.empty();
    }

    /**
     * The JDK home actions/setup-java exports as {@code JAVA_HOME_<major>_X64}
     * (or {@code _ARM64}) for {@code version} ({@code 1.8} reads major 8).
     */
    static Optional<Path> setupJavaHome(String version, Map<String, String> env) {
        String major = version.startsWith("1.") ? version.substring(2) : version;
        for (String arch : List.of("X64", "ARM64")) {
            String home = env.get("JAVA_HOME_" + major + "_" + arch);
            if (home != null && !home.isBlank()
                    && Files.isExecutable(Path.of(home).resolve("bin").resolve("java"))) {
                return Optional.of(Path.of(home));
            }
        }
        return Optional.empty();
    }

    /** One {@code /usr/libexec/java_home -v <version>} query, best-effort. */
    private static Optional<Path> macJavaHome(String version) {
        try {
            Process process = new ProcessBuilder(MAC_JAVA_HOME_TOOL, "-v", version)
                .redirectErrorStream(false)
                .start();
            String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8).strip();
            int exitCode = process.waitFor();
            if (exitCode == 0 && !output.isBlank()) {
                Path home = Path.of(output);
                if (Files.isExecutable(home.resolve("bin").resolve("java"))) {
                    return Optional.of(home);
                }
            }
        } catch (IOException e) {
            // Fall through: resolution is best-effort, like the Makefile.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // Build-step execution.
    // ------------------------------------------------------------------

    private static ServerLaunchException missingComponent(String language, ComponentId component) {
        return new ServerLaunchException(language, ServerLaunchException.Category.RESOLVE,
            "the " + language + " Language_Server launch requires the resolved '" + component
                + "' directory, but that component was not materialized for this run");
    }

    /**
     * Run one synchronous stamp-and-install step to completion in
     * {@code directory}. A step that cannot start, is interrupted, or exits
     * non-zero is a {@code BUILD} launch failure naming the step and carrying
     * the tool output (Requirement 2.5).
     */
    private static void runBuildStep(String language, String step, List<String> command,
            Path directory, Optional<Path> javaHome) throws ServerLaunchException {
        Instant startedAt = Instant.now();
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(directory.toFile());
            javaHome.ifPresent(home -> builder.environment().put("JAVA_HOME", home.toString()));
            builder.redirectErrorStream(true);

            Process process;
            try {
                process = builder.start();
            } catch (IOException e) {
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command, e.getMessage()), e);
            }

            String output;
            int exitCode;
            try {
                output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                exitCode = process.waitFor();
            } catch (IOException e) {
                process.destroyForcibly();
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command, e.getMessage()), e);
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command, "interrupted while waiting"), e);
            }

            if (exitCode != 0) {
                throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                    buildFailureMessage(language, step, command,
                        "exit code " + exitCode + "; output:\n" + tail(output)));
            }
        } finally {
            LaunchTimings.log(language, step, startedAt);
        }
    }

    /**
     * {@code mvn versions:revert}, best-effort: always attempted (the resolved
     * tree must not stay stamped), never allowed to mask the install result —
     * the Makefile's {@code mvn -q versions:revert || true}.
     */
    private static void revertBestEffort(Path libraryDir, Optional<Path> javaHome) {
        try {
            runBuildStep("java", "restore the pom version (mvn versions:revert)",
                versionsRevertCommand(), libraryDir, javaHome);
        } catch (ServerLaunchException e) {
            System.err.println("WARNING: mvn versions:revert failed in " + libraryDir
                + " — the resolved Java library tree may be left stamped: " + e.getMessage());
        }
    }

    private static String buildFailureMessage(String language, String step,
            List<String> command, String detail) {
        return "the " + language + " Language_Server build step '" + step
            + "' failed (" + String.join(" ", command) + "): " + detail;
    }

    private static String tail(String output) {
        String trimmed = output.strip();
        if (trimmed.length() <= MAX_FAILURE_OUTPUT_CHARS) {
            return trimmed;
        }
        return "..." + trimmed.substring(trimmed.length() - MAX_FAILURE_OUTPUT_CHARS);
    }
}
