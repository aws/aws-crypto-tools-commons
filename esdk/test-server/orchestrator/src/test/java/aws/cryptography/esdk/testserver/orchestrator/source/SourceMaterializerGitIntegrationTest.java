package aws.cryptography.esdk.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Real-git integration tests for {@link SourceMaterializer}: fixture
 * repositories are built with real {@code git} commands under {@code @TempDir}
 * and materialized through {@code file://} URLs — hermetic, no network. The
 * pure/cheap coverage lives in {@link SourceMaterializerTest}; these exercise
 * actual clone, branch, path, and dirty-detection behavior: branch checkout,
 * a nonexistent branch, a missing Server_Location path, honest working-tree
 * dirt detection, and a poisoned nested {@code commons-configuration.json}
 * that must never affect resolution (materialization looks only one level
 * deep by construction).
 */
class SourceMaterializerGitIntegrationTest {

    @TempDir
    Path fixtures;

    @TempDir
    Path scratch;

    // ------------------------------------------------------------------
    // (a) Clone at a specific branch resolves that branch's exact commit
    // ------------------------------------------------------------------

    @Test
    @DisplayName("cloning at a branch succeeds with the branch's exact commit (Req 3.3)")
    void cloneAtBranchResolvesThatBranchsCommit() throws Exception {
        Path repo = initRepo(fixtures.resolve("upstream"));
        commitFile(repo, "esdk/test-server/server/marker.txt", "main content", "main commit");
        String mainCommit = gitOutput(repo, "rev-parse", "HEAD");
        git(repo, "checkout", "-b", "feature");
        commitFile(repo, "esdk/test-server/server/marker.txt", "feature content", "feature commit");
        String featureCommit = gitOutput(repo, "rev-parse", "HEAD");
        assertNotEquals(mainCommit, featureCommit, "fixture branches diverge");

        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(fileUrl(repo), "feature", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        assertEquals(1, sources.outcomes().size());
        var success = assertInstanceOf(MaterializedSources.Success.class,
            sources.outcomes().get(0));
        assertEquals(featureCommit, success.commit(),
            "the clone stands at exactly the requested branch's head");
        assertEquals("feature", success.reference());
        assertNull(success.dirty(), "clone components carry no dirty flag");
        assertTrue(Files.isDirectory(success.directory()),
            "resolved directory exists: " + success.directory());
        assertEquals("feature content",
            Files.readString(success.directory().resolve("marker.txt")).trim(),
            "the resolved directory holds the branch's content, not main's");
    }

    // ------------------------------------------------------------------
    // (b) Nonexistent branch → Failure naming url + branch
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a nonexistent branch is a Failure naming the URL and the branch (Req 4.10)")
    void nonexistentBranchFailsNamingUrlAndBranch() throws Exception {
        Path repo = initRepo(fixtures.resolve("upstream"));
        commitFile(repo, "README.md", "hello", "initial commit");
        String url = fileUrl(repo);

        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(url, "no-such-branch", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        var failure = assertInstanceOf(MaterializedSources.Failure.class,
            sources.outcomes().get(0));
        assertEquals(url, failure.attemptedRepository());
        assertEquals("no-such-branch", failure.attemptedReference());
        assertTrue(failure.cause().contains(url),
            "the cause names the repository URL: " + failure.cause());
        assertTrue(failure.cause().contains("no-such-branch"),
            "the cause names the branch that could not be obtained: " + failure.cause());
        assertFalse(sources.allSucceeded());
    }

    // ------------------------------------------------------------------
    // (c) Missing Server_Location path → Failure naming repo/ref/path
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a missing Server_Location path is a Failure naming repository, ref, and path (Req 3.6)")
    void missingPathInCloneFailsNamingCoordinates() throws Exception {
        Path repo = initRepo(fixtures.resolve("upstream"));
        commitFile(repo, "README.md", "hello", "initial commit");
        String url = fileUrl(repo);

        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(url, "main", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        var failure = assertInstanceOf(MaterializedSources.Failure.class,
            sources.outcomes().get(0));
        assertEquals(url, failure.attemptedRepository());
        assertEquals("main", failure.attemptedReference());
        assertEquals("esdk/test-server/server", failure.attemptedPath());
        assertTrue(failure.cause().contains("esdk/test-server/server"),
            "the cause names the missing path: " + failure.cause());
        assertTrue(failure.cause().contains(url),
            "the cause names the repository: " + failure.cause());
        assertTrue(failure.cause().contains("main"),
            "the cause names the reference: " + failure.cause());
    }

    // ------------------------------------------------------------------
    // (d) Working-tree dirt is detected honestly
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a clean fixture working tree materializes with dirty=false (Req 5.7)")
    void cleanWorkingTreeIsNotDirty() throws Exception {
        Path repo = initRepo(fixtures.resolve("worktree"));
        commitFile(repo, "esdk/lib.txt", "library", "initial commit");

        var plan = new ResolvedComponentPlan(
            ComponentId.library("java"),
            new SourcePlan.WorkingTree(repo, "esdk"),
            ResolutionReason.WORKING_TREE);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        var success = assertInstanceOf(MaterializedSources.Success.class,
            sources.outcomes().get(0));
        assertEquals(Boolean.FALSE, success.dirty(),
            "a freshly committed tree has no uncommitted modifications");
        assertEquals(gitOutput(repo, "rev-parse", "HEAD"), success.commit());
        assertEquals("main", success.reference(), "the checked-out branch is recorded");
    }

    @Test
    @DisplayName("an uncommitted modification flips the working tree to dirty=true (Req 5.7)")
    void uncommittedModificationIsDetectedAsDirty() throws Exception {
        Path repo = initRepo(fixtures.resolve("worktree"));
        commitFile(repo, "esdk/lib.txt", "library", "initial commit");
        // Modify a tracked file without committing.
        Files.writeString(repo.resolve("esdk/lib.txt"), "uncommitted local change");

        var plan = new ResolvedComponentPlan(
            ComponentId.library("java"),
            new SourcePlan.WorkingTree(repo, "esdk"),
            ResolutionReason.WORKING_TREE);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        var success = assertInstanceOf(MaterializedSources.Success.class,
            sources.outcomes().get(0));
        assertEquals(Boolean.TRUE, success.dirty(),
            "an uncommitted modification must be reported (Requirement 5.7)");
        assertEquals(gitOutput(repo, "rev-parse", "HEAD"), success.commit(),
            "the commit is still the checked-out HEAD — dirt does not change identity");
    }

    // ------------------------------------------------------------------
    // (e) A poisoned nested commons-configuration.json never affects
    //     resolution — one level deep by construction
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a poisoned nested commons-configuration.json does not affect resolution (Req 3.7)")
    void poisonedNestedConfigurationIsInert() throws Exception {
        // Two fixtures identical except one carries a commons-configuration.json
        // full of absurd overrides. Materialization must treat them identically.
        Path clean = initRepo(fixtures.resolve("clean"));
        commitFile(clean, "esdk/test-server/server/marker.txt", "server", "server commit");

        Path poisoned = initRepo(fixtures.resolve("poisoned"));
        commitFile(poisoned, "esdk/test-server/server/marker.txt", "server", "server commit");
        commitFile(poisoned, "esdk/test-server/commons-configuration.json", """
            {
              "commonsRepository": {
                "name": "evil-commons",
                "url": "https://example.invalid/evil-commons.git",
                "branch": "hijacked"
              },
              "product": "not-esdk",
              "supportedFeatures": ["nonsense"],
              "unsupportedFeatures": ["streaming", "MPL"],
              "configurationOverrides": [
                {
                  "language": "java",
                  "libraryRepository": {
                    "name": "evil-java",
                    "url": "https://example.invalid/evil-java.git",
                    "branch": "hijacked"
                  },
                  "majorVersion": 999,
                  "port": 1,
                  "serverLocation": {
                    "repository": "evil-java",
                    "ref": "hijacked",
                    "path": "evil/path"
                  }
                }
              ]
            }
            """, "poison commit");

        var cleanPlan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(fileUrl(clean), "main", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);
        var poisonedPlan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(fileUrl(poisoned), "main", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        var materializer = new SourceMaterializer(scratch);
        MaterializedSources cleanSources = materializer.materialize(List.of(cleanPlan));
        MaterializedSources poisonedSources = materializer.materialize(List.of(poisonedPlan));

        // Both materialize identically: a Success at the planned path with the
        // planned reason and the fixture's own head commit.
        var cleanSuccess = assertInstanceOf(MaterializedSources.Success.class,
            cleanSources.outcomes().get(0));
        var poisonedSuccess = assertInstanceOf(MaterializedSources.Success.class,
            poisonedSources.outcomes().get(0));

        assertEquals(gitOutput(clean, "rev-parse", "HEAD"), cleanSuccess.commit());
        assertEquals(gitOutput(poisoned, "rev-parse", "HEAD"), poisonedSuccess.commit(),
            "the poisoned repository resolves to its own head — nothing re-resolved");
        assertEquals(cleanSuccess.reference(), poisonedSuccess.reference());
        assertEquals(cleanSuccess.reason(), poisonedSuccess.reason(),
            "the resolution reason is the planner's, untouched by nested config");
        assertTrue(poisonedSuccess.directory().endsWith(Path.of("esdk/test-server/server")),
            "the resolved directory is exactly the planned path: "
                + poisonedSuccess.directory());

        // None of the poisoned override coordinates leak into the outcome.
        String outcome = poisonedSuccess.toString();
        assertFalse(outcome.contains("evil"),
            "no poisoned coordinate appears in the outcome: " + outcome);
        assertFalse(outcome.contains("hijacked"),
            "no poisoned reference appears in the outcome: " + outcome);
    }

    // ------------------------------------------------------------------
    // (f) A pre-existing clone at the remote tip is reused; a stale or
    //     non-repository directory is wiped and cloned fresh
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a pre-existing clone whose HEAD equals the remote tip is reused in place")
    void existingCloneAtRemoteTipIsReused() throws Exception {
        Path repo = initRepo(fixtures.resolve("upstream"));
        commitFile(repo, "esdk/test-server/server/marker.txt", "content", "initial commit");
        String tip = gitOutput(repo, "rev-parse", "HEAD");

        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(fileUrl(repo), "main", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        var materializer = new SourceMaterializer(scratch);
        var first = assertInstanceOf(MaterializedSources.Success.class,
            materializer.materialize(List.of(plan)).outcomes().get(0));
        // A build output in the materialized clone: survives only without a wipe.
        Path buildOutput = first.directory().resolve("build-output.txt");
        Files.writeString(buildOutput, "built at " + tip);

        var second = assertInstanceOf(MaterializedSources.Success.class,
            materializer.materialize(List.of(plan)).outcomes().get(0));

        assertEquals(tip, second.commit());
        assertEquals(first.directory(), second.directory());
        assertTrue(Files.isRegularFile(buildOutput),
            "the reused clone keeps its contents — no wipe happened");
    }

    @Test
    @DisplayName("a pre-existing clone behind the remote tip is wiped and cloned fresh")
    void existingCloneBehindRemoteTipIsRecloned() throws Exception {
        Path repo = initRepo(fixtures.resolve("upstream"));
        commitFile(repo, "esdk/test-server/server/marker.txt", "old", "initial commit");

        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(fileUrl(repo), "main", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        var materializer = new SourceMaterializer(scratch);
        var first = assertInstanceOf(MaterializedSources.Success.class,
            materializer.materialize(List.of(plan)).outcomes().get(0));
        Path buildOutput = first.directory().resolve("build-output.txt");
        Files.writeString(buildOutput, "stale build output");

        // The upstream branch advances: the existing clone is now stale.
        commitFile(repo, "esdk/test-server/server/marker.txt", "new", "advance");
        String newTip = gitOutput(repo, "rev-parse", "HEAD");

        var second = assertInstanceOf(MaterializedSources.Success.class,
            materializer.materialize(List.of(plan)).outcomes().get(0));

        assertEquals(newTip, second.commit(), "the fresh clone stands at the new tip");
        assertEquals("new",
            Files.readString(second.directory().resolve("marker.txt")).trim());
        assertFalse(Files.exists(buildOutput),
            "the stale clone was wiped — nothing carried over");
    }

    @Test
    @DisplayName("a non-repository directory at the clone target is wiped and cloned fresh")
    void nonRepositoryTargetIsRecloned() throws Exception {
        Path repo = initRepo(fixtures.resolve("upstream"));
        commitFile(repo, "esdk/test-server/server/marker.txt", "content", "initial commit");
        String tip = gitOutput(repo, "rev-parse", "HEAD");

        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.Clone(fileUrl(repo), "main", "esdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY);

        // Occupy the target with a plain directory (no .git).
        Path target = scratch.resolve(SourceMaterializer.cloneDirectoryName(
            new SourceMaterializer.CloneKey(fileUrl(repo), "main")));
        Files.createDirectories(target);
        Files.writeString(target.resolve("junk.txt"), "not a clone");

        var success = assertInstanceOf(MaterializedSources.Success.class,
            new SourceMaterializer(scratch).materialize(List.of(plan)).outcomes().get(0));

        assertEquals(tip, success.commit());
        assertFalse(Files.exists(target.resolve("junk.txt")),
            "the non-repository occupant was wiped before the clone");
    }

    // ------------------------------------------------------------------
    // Fixture-repo plumbing (real git via ProcessBuilder, all under @TempDir)
    // ------------------------------------------------------------------

    /** Create a git repository at {@code dir} on branch {@code main}, locally configured. */
    private static Path initRepo(Path dir) throws Exception {
        Files.createDirectories(dir);
        git(dir, "init");
        git(dir, "checkout", "-b", "main");
        git(dir, "config", "user.email", "fixture@example.invalid");
        git(dir, "config", "user.name", "Fixture Builder");
        git(dir, "config", "commit.gpgsign", "false");
        return dir;
    }

    /** Write {@code relativePath} (creating parents) and commit it. */
    private static void commitFile(
            Path repo, String relativePath, String content, String message) throws Exception {
        Path file = repo.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
        git(repo, "add", ".");
        git(repo, "commit", "-m", message);
    }

    /** The {@code file://} clone URL for a fixture repository. */
    private static String fileUrl(Path repo) {
        // Path.toUri() yields file:///abs/path/ — git accepts it as a clone URL.
        return repo.toUri().toString();
    }

    /** Run {@code git <args>} in {@code dir}, asserting success. */
    private static void git(Path dir, String... args) throws Exception {
        runGit(dir, args);
    }

    /** Run {@code git <args>} in {@code dir}, asserting success, returning trimmed output. */
    private static String gitOutput(Path dir, String... args) throws Exception {
        return runGit(dir, args);
    }

    private static String runGit(Path dir, String... args)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(args.length + 1);
        command.add("git");
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command)
            .directory(dir.toFile())
            .redirectErrorStream(true)
            .start();
        String output = new String(
            process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS),
            "fixture git command timed out: " + String.join(" ", command));
        assertEquals(0, process.exitValue(),
            "fixture git command failed: " + String.join(" ", command) + "\n" + output);
        return output.trim();
    }
}
