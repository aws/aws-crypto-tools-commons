package aws.cryptography.testserver.orchestrator.source;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Executes the {@link SourceResolver}'s plans (design "SourceMaterializer"):
 * the single place the resolution pipeline performs I/O.
 *
 * <ul>
 *   <li>{@link SourcePlan.Clone}: {@code git clone --depth 1 --single-branch
 *       --branch <ref> <url>} into a scratch directory, one clone per distinct
 *       {@code (url, ref)} pair — components sharing coordinates share the
 *       clone (Requirement 3.3). A pre-existing scratch directory whose
 *       {@code HEAD} equals the live remote tip of the ref is reused in place;
 *       otherwise it is wiped and cloned fresh.</li>
 *   <li>{@link SourcePlan.WorkingTree}: the already-present tree is used in
 *       place — nothing is cloned (Requirements 3.4, 4.2).</li>
 *   <li>Every component: the plan's path must exist under the clone or
 *       working tree root (Requirement 3.6); the resolved commit is
 *       {@code git rev-parse HEAD} (Requirement 5.1); working trees
 *       additionally report the checked-out branch and whether
 *       {@code git status --porcelain} is non-empty (Requirement 5.7).</li>
 * </ul>
 *
 * <p><b>Failures are outcomes, never exceptions.</b> A clone failure, a
 * nonexistent branch, a missing path, or a failing git query is captured as a
 * {@link MaterializedSources.Failure} carrying the attempted coordinates and
 * the cause (Requirements 3.6, 4.10, 5.4); nothing thrown by git or the
 * filesystem escapes {@link #materialize} — the fail-closed pipeline gate
 * decides what a failure means.
 *
 * <p><b>One level deep by construction</b> (Requirement 3.7): this class only
 * clones, checks paths, and queries commits. It never reads a materialized
 * repository's {@code commons-configuration.json} or Configuration_Overrides —
 * no configuration parsing exists on this code path, so a repository obtained
 * for a Server_Location cannot trigger further context-dependent resolution.
 */
public final class SourceMaterializer implements Materializer {

    /** A distinct clone the plans require: one {@code git clone} per key. */
    record CloneKey(String url, String ref) {
    }

    private static final Duration GIT_TIMEOUT = Duration.ofMinutes(10);

    private final Path scratchDirectory;

    /**
     * @param scratchDirectory the directory clones land in (e.g. under
     *                         {@code build/} or a caller-supplied
     *                         temp dir); created on demand
     */
    public SourceMaterializer(Path scratchDirectory) {
        if (scratchDirectory == null) {
            throw new IllegalArgumentException("scratchDirectory is required");
        }
        this.scratchDirectory = scratchDirectory;
    }

    /**
     * The distinct {@code (url, ref)} pairs the plans' clone components
     * require, in first-appearance order. Pure; exposed for the dedup unit
     * tests — {@link #materialize} performs exactly one {@code git clone} per
     * returned key.
     */
    static List<CloneKey> distinctCloneKeys(List<ResolvedComponentPlan> plans) {
        List<CloneKey> keys = new ArrayList<>();
        for (ResolvedComponentPlan plan : plans) {
            if (plan.plan() instanceof SourcePlan.Clone clone) {
                CloneKey key = new CloneKey(clone.url(), clone.ref());
                if (!keys.contains(key)) {
                    keys.add(key);
                }
            }
        }
        return List.copyOf(keys);
    }

    /**
     * The scratch subdirectory a clone of {@code key} lands in: readable
     * (repository name + ref) and collision-free (a suffix derived from the
     * full {@code (url, ref)} pair). Pure; exposed for the unit tests.
     */
    static String cloneDirectoryName(CloneKey key) {
        String repo = key.url().replaceAll("/+$", "");
        int slash = Math.max(repo.lastIndexOf('/'), repo.lastIndexOf(':'));
        if (slash >= 0) {
            repo = repo.substring(slash + 1);
        }
        if (repo.endsWith(".git")) {
            repo = repo.substring(0, repo.length() - 4);
        }
        String readable = sanitize(repo) + "@" + sanitize(key.ref());
        String unique = String.format(Locale.ROOT, "%08x",
            (key.url() + "\n" + key.ref()).hashCode());
        return readable + "-" + unique;
    }

    private static String sanitize(String value) {
        String sanitized = value.replaceAll("[^A-Za-z0-9._-]", "_");
        return sanitized.isEmpty() ? "_" : sanitized;
    }

    /**
     * Execute every plan: clone each distinct {@code (url, ref)} once, verify
     * each component's path, identify commits, and detect working-tree dirt.
     * Always returns one outcome per plan, in plan order; never throws for a
     * materialization failure.
     */
    @Override
    public MaterializedSources materialize(List<ResolvedComponentPlan> plans) {
        // Phase 1: one clone per distinct (url, ref).
        Map<CloneKey, CloneResult> clones = new LinkedHashMap<>();
        for (CloneKey key : distinctCloneKeys(plans)) {
            clones.put(key, cloneOnce(key));
        }

        // Phase 2: per-root working-tree identity, computed once per root.
        Map<Path, TreeResult> trees = new LinkedHashMap<>();

        List<MaterializedSources.Outcome> outcomes = new ArrayList<>(plans.size());
        for (ResolvedComponentPlan plan : plans) {
            outcomes.add(switch (plan.plan()) {
                case SourcePlan.Clone clone ->
                    cloneOutcome(plan, clone, clones.get(new CloneKey(clone.url(), clone.ref())));
                case SourcePlan.WorkingTree tree ->
                    workingTreeOutcome(plan, tree,
                        trees.computeIfAbsent(tree.root(), this::inspectWorkingTree));
            });
        }
        return new MaterializedSources(outcomes);
    }

    // ------------------------------------------------------------------
    // Clones
    // ------------------------------------------------------------------

    /** A completed clone attempt: the root + commit on success, else the cause. */
    private record CloneResult(Path root, String commit, String failureCause) {
        static CloneResult success(Path root, String commit) {
            return new CloneResult(root, commit, null);
        }

        static CloneResult failure(String cause) {
            return new CloneResult(null, null, cause);
        }

        boolean failed() {
            return failureCause != null;
        }
    }

    private CloneResult cloneOnce(CloneKey key) {
        Path target = scratchDirectory.resolve(cloneDirectoryName(key));
        CloneResult reused = reuseExistingClone(key, target);
        if (reused != null) {
            return reused;
        }
        try {
            if (Files.exists(target)) {
                deleteRecursively(target); // stale clone from an earlier run
            }
            Files.createDirectories(scratchDirectory);
        } catch (IOException e) {
            return CloneResult.failure("could not prepare scratch directory "
                + target + ": " + e.getMessage());
        }

        GitResult clone = git(scratchDirectory,
            "clone", "--depth", "1", "--single-branch", "--branch", key.ref(),
            key.url(), target.toString());
        if (clone.failed()) {
            return CloneResult.failure("git clone failed for " + key.url()
                + " at branch " + key.ref() + ": " + clone.describeFailure());
        }

        GitResult head = git(target, "rev-parse", "HEAD");
        if (head.failed()) {
            return CloneResult.failure("git rev-parse HEAD failed in clone of "
                + key.url() + " at branch " + key.ref() + ": " + head.describeFailure());
        }
        return CloneResult.success(target, head.output().trim());
    }

    /**
     * Reuse {@code target} as the clone of {@code key} when it is already a
     * git repository whose {@code HEAD} equals the live remote tip of
     * {@code refs/heads/<ref>} (e.g. a CI-cache-restored directory from an
     * earlier run of the same commit). Returns {@code null} — caller wipes and
     * clones fresh — when the directory is absent, not a repository, the tip
     * cannot be verified, or the commits differ.
     */
    private CloneResult reuseExistingClone(CloneKey key, Path target) {
        if (!Files.isDirectory(target.resolve(".git"))) {
            return null;
        }
        GitResult head = git(target, "rev-parse", "HEAD");
        if (head.failed()) {
            return null;
        }
        GitResult remote = git(target, "ls-remote", key.url(), "refs/heads/" + key.ref());
        if (remote.failed()) {
            return null;
        }
        String tip = remote.output().strip();
        int end = tip.indexOf('\t');
        if (end > 0) {
            tip = tip.substring(0, end);
        }
        if (tip.isEmpty() || !tip.equals(head.output().trim())) {
            return null;
        }
        return CloneResult.success(target, tip);
    }

    private MaterializedSources.Outcome cloneOutcome(
            ResolvedComponentPlan plan, SourcePlan.Clone clone, CloneResult result) {
        if (result.failed()) {
            return new MaterializedSources.Failure(
                plan.component(), plan.plan(), plan.reason(), result.failureCause());
        }
        Path directory = result.root().resolve(clone.path()).normalize();
        if (!Files.isDirectory(directory)) {
            return new MaterializedSources.Failure(
                plan.component(), plan.plan(), plan.reason(),
                "path " + clone.path() + " does not exist in " + clone.url()
                    + " at branch " + clone.ref());
        }
        return new MaterializedSources.Success(
            plan.component(), plan.plan(), plan.reason(),
            directory, result.commit(), clone.ref(), null);
    }

    // ------------------------------------------------------------------
    // Working trees
    // ------------------------------------------------------------------

    /** A working-tree inspection: commit + branch + dirt on success, else the cause. */
    private record TreeResult(String commit, String branch, Boolean dirty, String failureCause) {
        static TreeResult success(String commit, String branch, boolean dirty) {
            return new TreeResult(commit, branch, dirty, null);
        }

        static TreeResult failure(String cause) {
            return new TreeResult(null, null, null, cause);
        }

        boolean failed() {
            return failureCause != null;
        }
    }

    private TreeResult inspectWorkingTree(Path root) {
        if (!Files.isDirectory(root)) {
            return TreeResult.failure("working tree root " + root + " does not exist");
        }
        GitResult head = git(root, "rev-parse", "HEAD");
        if (head.failed()) {
            return TreeResult.failure("git rev-parse HEAD failed in working tree "
                + root + ": " + head.describeFailure());
        }
        GitResult branch = git(root, "rev-parse", "--abbrev-ref", "HEAD");
        if (branch.failed()) {
            return TreeResult.failure("git rev-parse --abbrev-ref HEAD failed in working tree "
                + root + ": " + branch.describeFailure());
        }
        GitResult status = git(root, "status", "--porcelain");
        if (status.failed()) {
            return TreeResult.failure("git status --porcelain failed in working tree "
                + root + ": " + status.describeFailure());
        }
        return TreeResult.success(
            head.output().trim(), branch.output().trim(), !status.output().isBlank());
    }

    private MaterializedSources.Outcome workingTreeOutcome(
            ResolvedComponentPlan plan, SourcePlan.WorkingTree tree, TreeResult result) {
        if (result.failed()) {
            return new MaterializedSources.Failure(
                plan.component(), plan.plan(), plan.reason(), result.failureCause());
        }
        Path directory = tree.root().resolve(tree.path()).normalize();
        if (!Files.isDirectory(directory)) {
            return new MaterializedSources.Failure(
                plan.component(), plan.plan(), plan.reason(),
                "path " + tree.path() + " does not exist in working tree " + tree.root());
        }
        return new MaterializedSources.Success(
            plan.component(), plan.plan(), plan.reason(),
            directory, result.commit(), result.branch(), result.dirty());
    }

    // ------------------------------------------------------------------
    // Git subprocess plumbing
    // ------------------------------------------------------------------

    /** One completed git invocation: exit code and combined stdout+stderr. */
    private record GitResult(int exitCode, String output) {
        boolean failed() {
            return exitCode != 0;
        }

        String describeFailure() {
            String trimmed = output.strip();
            if (trimmed.length() > 500) {
                trimmed = trimmed.substring(0, 500) + "…";
            }
            return "exit " + exitCode + (trimmed.isEmpty() ? "" : " — " + trimmed);
        }
    }

    /**
     * Run {@code git <args>} in {@code workingDirectory}, capturing combined
     * output. Never throws: an I/O error, interrupt, or timeout becomes a
     * non-zero {@link GitResult} whose output carries the cause.
     */
    private static GitResult git(Path workingDirectory, String... args) {
        List<String> command = new ArrayList<>(args.length + 1);
        command.add("git");
        command.addAll(List.of(args));
        try {
            ProcessBuilder builder = new ProcessBuilder(command)
                .directory(workingDirectory.toFile())
                .redirectErrorStream(true);
            // Fail rather than hang on credential prompts for unreachable repos.
            builder.environment().put("GIT_TERMINAL_PROMPT", "0");
            Process process = builder.start();
            String output = new String(
                process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!process.waitFor(GIT_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new GitResult(-1, "git " + String.join(" ", args)
                    + " timed out after " + GIT_TIMEOUT.toSeconds() + "s");
            }
            return new GitResult(process.exitValue(), output);
        } catch (IOException e) {
            return new GitResult(-1, "failed to run git: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new GitResult(-1, "interrupted while running git");
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted((a, b) -> b.getNameCount() - a.getNameCount()).toList()) {
                Files.delete(path);
            }
        }
    }
}
