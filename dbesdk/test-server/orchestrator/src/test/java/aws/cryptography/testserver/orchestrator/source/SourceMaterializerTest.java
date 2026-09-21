package aws.cryptography.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for the SourceMaterializer's pure parts (clone dedup, directory
 * naming, outcome shaping) plus cheap working-tree checks against the enclosing
 * real commons repository — no network, no cloning. The real-git clone
 * integration tests live in {@link SourceMaterializerGitIntegrationTest}.
 */
class SourceMaterializerTest {

    @TempDir
    Path scratch;

    // ------------------------------------------------------------------
    // Pure: clone deduplication (one git clone per distinct (url, ref))
    // ------------------------------------------------------------------

    @Test
    @DisplayName("components sharing (url, ref) plan exactly one clone, in first-appearance order")
    void distinctCloneKeysDeduplicates() {
        String url = "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git";
        List<ResolvedComponentPlan> plans = List.of(
            new ResolvedComponentPlan(ComponentId.library("java"),
                new SourcePlan.Clone(url, "main", "esdk"),
                ResolutionReason.CONFIGURATION_ENTRY),
            new ResolvedComponentPlan(ComponentId.server("java"),
                new SourcePlan.Clone(url, "main", "dbesdk/test-server/server"),
                ResolutionReason.CONFIGURATION_ENTRY),
            new ResolvedComponentPlan(ComponentId.library("python"),
                new SourcePlan.Clone("https://github.com/aws/aws-encryption-sdk-python",
                    "master", "."),
                ResolutionReason.CONFIGURATION_ENTRY),
            new ResolvedComponentPlan(ComponentId.server("python"),
                new SourcePlan.WorkingTree(Path.of("/work/commons"),
                    "dbesdk/test-server/orchestrator"),
                ResolutionReason.CONFIGURATION_ENTRY));

        List<SourceMaterializer.CloneKey> keys = SourceMaterializer.distinctCloneKeys(plans);

        assertEquals(List.of(
            new SourceMaterializer.CloneKey(url, "main"),
            new SourceMaterializer.CloneKey(
                "https://github.com/aws/aws-encryption-sdk-python", "master")),
            keys, "library + server sharing (url, ref) collapse to one clone; "
                + "working trees plan no clone");
    }

    @Test
    @DisplayName("same url at different refs are distinct clones")
    void distinctCloneKeysKeepsDifferentRefsApart() {
        String url = "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git";
        List<ResolvedComponentPlan> plans = List.of(
            new ResolvedComponentPlan(ComponentId.library("java"),
                new SourcePlan.Clone(url, "main", "esdk"),
                ResolutionReason.CONFIGURATION_ENTRY),
            new ResolvedComponentPlan(ComponentId.server("java"),
                new SourcePlan.Clone(url, "feature-branch", "dbesdk/test-server/server"),
                ResolutionReason.CONFIGURATION_OVERRIDE));

        assertEquals(2, SourceMaterializer.distinctCloneKeys(plans).size());
    }

    @Test
    @DisplayName("clone directory names are filesystem-safe and distinct per (url, ref)")
    void cloneDirectoryNames() {
        var main = new SourceMaterializer.CloneKey(
            "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git", "main");
        var feature = new SourceMaterializer.CloneKey(
            "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git", "kessplas/esdk-test-server");

        String mainDir = SourceMaterializer.cloneDirectoryName(main);
        String featureDir = SourceMaterializer.cloneDirectoryName(feature);

        assertNotEquals(mainDir, featureDir);
        assertTrue(mainDir.startsWith("aws-database-encryption-sdk-dynamodb@main-"), mainDir);
        assertFalse(featureDir.contains("/"), "ref separators are sanitized: " + featureDir);
    }

    // ------------------------------------------------------------------
    // Pure: outcome shaping (what the Resolution_Record consumes)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a Failure exposes the attempted (repository, reference, path) coordinates")
    void failureCarriesAttemptedCoordinates() {
        var cloneFailure = new MaterializedSources.Failure(
            ComponentId.server("rust"),
            new SourcePlan.Clone("git@github.com:aws/aws-crypto-tools-rust.git",
                "main", "dbesdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY,
            "git clone failed: repository not found");

        assertEquals("git@github.com:aws/aws-crypto-tools-rust.git",
            cloneFailure.attemptedRepository());
        assertEquals("main", cloneFailure.attemptedReference());
        assertEquals("dbesdk/test-server/server", cloneFailure.attemptedPath());

        var treeFailure = new MaterializedSources.Failure(
            ComponentId.library("java"),
            new SourcePlan.WorkingTree(Path.of("/work/java-repo"), "esdk"),
            ResolutionReason.WORKING_TREE,
            "path esdk does not exist in working tree /work/java-repo");

        assertEquals("/work/java-repo", treeFailure.attemptedRepository());
        assertNull(treeFailure.attemptedReference(),
            "a working tree is used as checked out — no reference was requested");
        assertEquals("esdk", treeFailure.attemptedPath());
    }

    @Test
    @DisplayName("Success enforces the dirty flag: required for working trees, absent for clones")
    void successDirtyFlagShape() {
        var tree = new SourcePlan.WorkingTree(Path.of("/work/java-repo"), "esdk");
        var clone = new SourcePlan.Clone("url", "main", "esdk");

        assertThrows(IllegalArgumentException.class, () ->
            new MaterializedSources.Success(ComponentId.library("java"), tree,
                ResolutionReason.WORKING_TREE, Path.of("/work/java-repo/esdk"),
                "abc123", "main", null),
            "a working-tree Success without a dirty flag violates Requirement 5.7");
        assertThrows(IllegalArgumentException.class, () ->
            new MaterializedSources.Success(ComponentId.library("java"), clone,
                ResolutionReason.CONFIGURATION_ENTRY, Path.of("/scratch/x/esdk"),
                "abc123", "main", true),
            "a clone Success carries no dirty flag");
    }

    @Test
    @DisplayName("MaterializedSources partitions outcomes and answers per-component lookups")
    void materializedSourcesAccessors() {
        var success = new MaterializedSources.Success(
            ComponentId.library("java"),
            new SourcePlan.Clone("url", "main", "esdk"),
            ResolutionReason.CONFIGURATION_ENTRY,
            Path.of("/scratch/java@main/esdk"), "abc123", "main", null);
        var failure = new MaterializedSources.Failure(
            ComponentId.server("java"),
            new SourcePlan.Clone("url", "main", "dbesdk/test-server/server"),
            ResolutionReason.CONFIGURATION_ENTRY,
            "path does not exist");

        var sources = new MaterializedSources(List.of(success, failure));

        assertEquals(List.of(success, failure), sources.outcomes());
        assertEquals(List.of(success), sources.successes());
        assertEquals(List.of(failure), sources.failures());
        assertFalse(sources.allSucceeded());
        assertEquals(Optional.of(Path.of("/scratch/java@main/esdk")),
            sources.directoryOf(ComponentId.library("java")));
        assertEquals(Optional.empty(), sources.directoryOf(ComponentId.server("java")));

        assertTrue(new MaterializedSources(List.of(success)).allSucceeded());
    }

    // ------------------------------------------------------------------
    // Cheap local checks against the enclosing real repository (no cloning)
    // ------------------------------------------------------------------

    /** Walk up from the test's working directory to the enclosing git repo root. */
    private static Path enclosingRepoRoot() {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null && !Files.exists(dir.resolve(".git"))) {
            dir = dir.getParent();
        }
        assertNotNull(dir, "test must run inside the commons git repository");
        return dir;
    }

    @Test
    @DisplayName("working-tree plan: resolved directory, rev-parse HEAD commit, dirty flag (Req 5.7)")
    void workingTreeMaterializesFromTheEnclosingRepo() {
        Path root = enclosingRepoRoot();
        var plan = new ResolvedComponentPlan(
            ComponentId.server("python"),
            new SourcePlan.WorkingTree(root, "dbesdk/test-server/orchestrator"),
            ResolutionReason.CONFIGURATION_ENTRY);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        assertEquals(1, sources.outcomes().size());
        var success = assertInstanceOf(MaterializedSources.Success.class,
            sources.outcomes().get(0));
        assertEquals(root.resolve("dbesdk/test-server/orchestrator"), success.directory());
        assertTrue(success.commit().matches("[0-9a-f]{40}"),
            "commit is the working tree's rev-parse HEAD: " + success.commit());
        assertNotNull(success.dirty(), "working-tree components carry the dirty flag");
        assertFalse(success.reference().isBlank(), "the checked-out branch is recorded");
    }

    @Test
    @DisplayName("working-tree plan with a missing path fails naming the path (Req 3.6)")
    void workingTreeMissingPathIsAFailureOutcome() {
        Path root = enclosingRepoRoot();
        var plan = new ResolvedComponentPlan(
            ComponentId.server("java"),
            new SourcePlan.WorkingTree(root, "no/such/server/path"),
            ResolutionReason.WORKING_TREE);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        var failure = assertInstanceOf(MaterializedSources.Failure.class,
            sources.outcomes().get(0));
        assertEquals("no/such/server/path", failure.attemptedPath());
        assertTrue(failure.cause().contains("no/such/server/path"),
            "the cause names the missing path: " + failure.cause());
        assertFalse(sources.allSucceeded());
    }

    @Test
    @DisplayName("a nonexistent working-tree root is a failure outcome, not an exception")
    void workingTreeMissingRootIsAFailureOutcome() {
        var plan = new ResolvedComponentPlan(
            ComponentId.library("java"),
            new SourcePlan.WorkingTree(Path.of("/definitely/not/a/repo"), "esdk"),
            ResolutionReason.WORKING_TREE);

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(List.of(plan));

        var failure = assertInstanceOf(MaterializedSources.Failure.class,
            sources.outcomes().get(0));
        assertTrue(failure.cause().contains("/definitely/not/a/repo"),
            "the cause names the missing root: " + failure.cause());
    }

    @Test
    @DisplayName("library and server on the same working tree share one inspection and both resolve")
    void sharedWorkingTreeRootResolvesBothComponents() throws IOException {
        Path root = enclosingRepoRoot();
        List<ResolvedComponentPlan> plans = List.of(
            new ResolvedComponentPlan(ComponentId.library("python"),
                new SourcePlan.WorkingTree(root, "."),
                ResolutionReason.WORKING_TREE),
            new ResolvedComponentPlan(ComponentId.server("python"),
                new SourcePlan.WorkingTree(root, "dbesdk/test-server/orchestrator"),
                ResolutionReason.WORKING_TREE));

        MaterializedSources sources =
            new SourceMaterializer(scratch).materialize(plans);

        assertTrue(sources.allSucceeded());
        var library = sources.successOf(ComponentId.library("python")).orElseThrow();
        var server = sources.successOf(ComponentId.server("python")).orElseThrow();
        assertEquals(library.commit(), server.commit(),
            "components of one working tree share its checked-out commit");
        assertEquals(library.dirty(), server.dirty());
        assertEquals(root, library.directory());

        // No clone plan → nothing landed in the scratch directory.
        try (var entries = Files.list(scratch)) {
            assertEquals(0, entries.count(), "working-tree plans never clone");
        }
    }
}
