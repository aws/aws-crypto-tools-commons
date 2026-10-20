package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.testserver.orchestrator.source.SourcePlan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link JavaLaunchPlan}: the pure command construction
 * reproduces the aws-database-encryption-sdk-dynamodb Makefile's {@code build-live-esdk}
 * stamp-and-install flow and the server's {@code runServer} launch against the
 * resolved sources, and a run whose materialized sources lack the Java library
 * or server directory is a {@code RESOLVE} launch failure naming the language —
 * all without running a real Maven or Gradle build.
 */
class JavaLaunchPlanTest {

    private static final Path MODEL = Path.of("/repo/dbesdk/test-server/model");
    private static final Path LIBRARY = Path.of("/scratch/clones/aws-database-encryption-sdk-dynamodb/esdk");
    private static final Path SERVER = Path.of("/scratch/clones/aws-database-encryption-sdk-dynamodb/dbesdk/test-server/server");

    // ------------------------------------------------------------------
    // Pure command construction (the build-live-esdk flow, resolved sources).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the stamped version is distinct (0.0.0-testserver-<timestamp>) so mavenLocal provably resolves the live install")
    void stampedVersionIsDistinct() {
        String stamped = JavaLaunchPlan.stampVersion(Instant.parse("2026-07-01T12:34:56Z"));
        assertEquals("0.0.0-testserver-20260701123456", stamped);
        assertTrue(stamped.startsWith(JavaLaunchPlan.STAMP_PREFIX),
            "a 0.0.0- version can never collide with a published GA artifact");
    }

    @Test
    @DisplayName("the library is stamped with mvn versions:set keeping backup poms, like build-live-esdk")
    void versionsSet() {
        assertEquals(
            List.of("mvn", "-q", "-DnewVersion=0.0.0-testserver-20260701123456",
                "versions:set", "-DgenerateBackupPoms=true"),
            JavaLaunchPlan.versionsSetCommand("0.0.0-testserver-20260701123456"));
    }

    @Test
    @DisplayName("the install skips tests, jacoco, and javadoc, exactly as build-live-esdk does")
    void install() {
        List<String> command = JavaLaunchPlan.installCommand();
        assertEquals(
            List.of("mvn", "-q", "-DskipTests", "-Dmaven.test.skip=true",
                "-Djacoco.skip=true", "-Dmaven.javadoc.skip=true", "install"),
            command);
        assertTrue(command.contains("-DskipTests") && command.contains("-Dmaven.test.skip=true"),
            "a build artifact is being produced, not the ESDK's own suite gated");
    }

    @Test
    @DisplayName("the pom version is restored with mvn versions:revert")
    void versionsRevert() {
        assertEquals(List.of("mvn", "-q", "versions:revert"),
            JavaLaunchPlan.versionsRevertCommand());
    }

    @Test
    @DisplayName("the server runs via its own gradlew: runServer --args=<port> -PesdkVersion=<stamped> -PmodelDir=<commons model>")
    void serverCommand() {
        assertEquals(
            List.of(SERVER.resolve("gradlew").toString(),
                "runServer",
                "--args=8091",
                "-PesdkVersion=0.0.0-testserver-20260701123456",
                "-PmodelDir=" + MODEL),
            JavaLaunchPlan.serverCommand(SERVER, 8091, "0.0.0-testserver-20260701123456", MODEL));
    }

    // ------------------------------------------------------------------
    // RESOLVE failure paths: missing materialized sources abort before any
    // Maven/Gradle step runs.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a run with no materialized java library is a RESOLVE failure naming the language")
    void missingLibraryIsResolveFailure(@TempDir Path tempDir) {
        JavaLaunchPlan plan = newPlan(tempDir);
        MaterializedSources sources = new MaterializedSources(List.of(serverSuccess()));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(javaEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("java", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("library:java"),
            "the abort must identify the missing component");
    }

    @Test
    @DisplayName("a run with no materialized java server is a RESOLVE failure naming the language")
    void missingServerIsResolveFailure(@TempDir Path tempDir) {
        JavaLaunchPlan plan = newPlan(tempDir);
        MaterializedSources sources = new MaterializedSources(List.of(librarySuccess()));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(javaEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertEquals("java", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains("server:java"),
            "the abort must identify the missing component");
    }

    @Test
    @DisplayName("empty materialized sources fail on the library first (nothing is spawned)")
    void emptySourcesFailOnLibrary(@TempDir Path tempDir) {
        JavaLaunchPlan plan = newPlan(tempDir);
        MaterializedSources sources = new MaterializedSources(List.of());

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(javaEntry(), sources));
        assertEquals(ServerLaunchException.Category.RESOLVE, ex.category());
        assertTrue(ex.getMessage().contains("library:java"));
    }

    // ------------------------------------------------------------------
    // BUILD failure path: an explicitly configured but unusable ESDK
    // JAVA_HOME is a BUILD failure naming the cause (no Maven step runs).
    // ------------------------------------------------------------------

    @Test
    @DisplayName("an explicit ESDK JAVA_HOME with no executable bin/java is a BUILD failure naming the cause")
    void unusableEsdkJavaHomeIsBuildFailure(@TempDir Path tempDir) {
        Path bogusHome = tempDir.resolve("not-a-jdk");
        JavaLaunchPlan plan = new JavaLaunchPlan(tempDir.resolve("work"), MODEL,
            bogusHome, null, new SubprocessLauncher(Duration.ofSeconds(1)));
        MaterializedSources sources =
            new MaterializedSources(List.of(librarySuccess(), serverSuccess()));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> plan.launch(javaEntry(), sources));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertEquals("java", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains(bogusHome.toString()),
            "the abort must name the unusable JAVA_HOME");
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a Dafny library whose stamp records its commit skips the transpile + publish")
    void stampedDafnyLibrarySkipsTheTranspile(@TempDir Path tempDir) throws IOException {
        Path project = Files.createDirectories(tempDir.resolve("repo/AwsCryptographyPrimitives"));
        Path library = Files.createDirectories(project.resolve("runtimes/java"));
        // Were the transpile to run, this target would leave a marker behind.
        Files.writeString(project.resolve("Makefile"), "build_java:\n\ttouch transpiled\n");
        String commit = "0123456789abcdef0123456789abcdef01234567";
        Files.writeString(project.resolve("." + JavaLaunchPlan.DAFNY_LIBRARY_STAMP + "-build-stamp"), commit);
        Path server = Files.createDirectories(tempDir.resolve("repo/test-server/java-v1-server"));
        MaterializedSources sources = new MaterializedSources(List.of(
            new MaterializedSources.Success(ComponentId.library("java"),
                new SourcePlan.Clone("git@github.com:aws/mpl.git", "main", "AwsCryptographyPrimitives/runtimes/java"),
                ResolutionReason.CONFIGURATION_ENTRY, library, commit, "main", null),
            new MaterializedSources.Success(ComponentId.server("java"),
                new SourcePlan.Clone("git@github.com:aws/mpl.git", "main", "test-server/java-v1-server"),
                ResolutionReason.CONFIGURATION_ENTRY, server, commit, "main", null)));

        // The server directory has no gradlew, so the launch itself fails;
        // what matters is that it got past the library build without Dafny.
        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> newPlan(tempDir.resolve("work")).launch(javaEntry(), sources));
        assertFalse(ex.getMessage().contains("requires Dafny"), ex.getMessage());
        assertFalse(Files.exists(project.resolve("transpiled")), "the transpile must not run");
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static JavaLaunchPlan newPlan(Path workDir) {
        // A short readiness window keeps any accidental launch fast; the
        // RESOLVE paths under test abort before the launcher is ever reached.
        return new JavaLaunchPlan(workDir, MODEL, null, null,
            new SubprocessLauncher(Duration.ofSeconds(1)));
    }

    private static ConfigurationEntry javaEntry() {
        return new ConfigurationEntry("java", 3, 8091, null, null, null, null);
    }

    private static MaterializedSources.Success librarySuccess() {
        return new MaterializedSources.Success(
            ComponentId.library("java"),
            new SourcePlan.Clone("git@github.com:aws/aws-database-encryption-sdk-dynamodb.git",
                "kessplas/esdk-test-server", "esdk"),
            ResolutionReason.CONFIGURATION_ENTRY,
            LIBRARY, "0123456789abcdef0123456789abcdef01234567",
            "kessplas/esdk-test-server", null);
    }

    private static MaterializedSources.Success serverSuccess() {
        return new MaterializedSources.Success(
            ComponentId.server("java"),
            new SourcePlan.Clone("git@github.com:aws/aws-database-encryption-sdk-dynamodb.git",
                "kessplas/esdk-test-server", "dbesdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY,
            SERVER, "89abcdef0123456789abcdef0123456789abcdef",
            "kessplas/esdk-test-server", null);
    }

    @Test
    @DisplayName("a JDK exported by actions/setup-java as JAVA_HOME_<major>_X64 is resolved, 1.8 reading major 8")
    void setupJavaHome(@TempDir Path jdk) throws IOException {
        Path javaBin = Files.createDirectories(jdk.resolve("bin")).resolve("java");
        Files.writeString(javaBin, "");
        javaBin.toFile().setExecutable(true);

        assertEquals(Optional.of(jdk),
            JavaLaunchPlan.setupJavaHome("17", Map.of("JAVA_HOME_17_X64", jdk.toString())));
        assertEquals(Optional.of(jdk),
            JavaLaunchPlan.setupJavaHome("1.8", Map.of("JAVA_HOME_8_ARM64", jdk.toString())));
        assertEquals(Optional.empty(),
            JavaLaunchPlan.setupJavaHome("11", Map.of("JAVA_HOME_17_X64", jdk.toString())));
    }
}
