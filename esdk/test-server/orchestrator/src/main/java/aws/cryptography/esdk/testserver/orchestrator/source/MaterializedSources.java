package aws.cryptography.esdk.testserver.orchestrator.source;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * The result of executing a run's resolution plans (design
 * "SourceMaterializer" output): exactly one {@link Outcome} per planned
 * component, each either a {@link Success} carrying the resolved directory and
 * commit identity, or a {@link Failure} carrying the attempted coordinates and
 * the cause. Materialization failures are data, not exceptions — the pipeline
 * gate (Requirement 3.6) and the Resolution_Record (task 4.1, Requirements 5.1,
 * 5.4, 5.7) consume these outcomes directly.
 */
public final class MaterializedSources {

    /**
     * One component's materialization outcome. Every outcome keeps the
     * component identity, the executed {@link SourcePlan} (which carries the
     * attempted coordinates: url + ref + path for clones, root + path for
     * working trees), and the {@link ResolutionReason} the resolver planned it
     * with (Requirement 5.2).
     */
    public sealed interface Outcome permits Success, Failure {
        ComponentId component();

        SourcePlan plan();

        ResolutionReason reason();
    }

    /**
     * A successfully materialized component.
     *
     * @param component the component this outcome materializes
     * @param plan      the executed plan (attempted coordinates)
     * @param reason    why this source was chosen (Requirement 5.2)
     * @param directory the resolved component directory (the clone or working
     *                  tree root joined with the plan's path)
     * @param commit    the resolved commit identifier, {@code git rev-parse
     *                  HEAD} of the clone or working tree (Requirement 5.1)
     * @param reference the reference the source stands at: the plan's ref for a
     *                  clone; the checked-out branch ({@code git rev-parse
     *                  --abbrev-ref HEAD}, {@code "HEAD"} when detached) for a
     *                  working tree
     * @param dirty     for working-tree components only: whether {@code git
     *                  status --porcelain} reported uncommitted modifications
     *                  (Requirement 5.7); {@code null} for clone components
     */
    public record Success(
        ComponentId component,
        SourcePlan plan,
        ResolutionReason reason,
        Path directory,
        String commit,
        String reference,
        Boolean dirty
    ) implements Outcome {
        public Success {
            if (component == null || plan == null || reason == null) {
                throw new IllegalArgumentException("component, plan, and reason are required");
            }
            if (directory == null || commit == null || commit.isBlank()
                    || reference == null || reference.isBlank()) {
                throw new IllegalArgumentException(
                    "a successful outcome requires a directory, a commit, and a reference");
            }
            boolean workingTree = plan instanceof SourcePlan.WorkingTree;
            if (workingTree && dirty == null) {
                throw new IllegalArgumentException(
                    "working-tree components carry a dirty flag (Requirement 5.7)");
            }
            if (!workingTree && dirty != null) {
                throw new IllegalArgumentException("clone components carry no dirty flag");
            }
        }

        /**
         * The clone or working-tree <em>root</em> this component was
         * materialized under — the directory the plan's path is relative to.
         * For working trees this is the plan's root; for clones it is
         * {@link #directory()} with the plan's relative path stripped (the
         * materializer resolves {@code directory = cloneRoot.resolve(path)}),
         * falling back to {@link #directory()} when the path cannot be
         * stripped. Lets the pipeline locate repository-level files — e.g. a
         * Language_Repository's
         * {@code esdk/test-server/commons-configuration.json} carrying its
         * Feature_Declaration — from a materialized server component
         * (Requirement 8.4).
         */
        public Path root() {
            return switch (plan) {
                case SourcePlan.WorkingTree tree -> tree.root();
                case SourcePlan.Clone clone -> stripRelative(directory, clone.path());
            };
        }
    }

    /**
     * {@code directory} with the relative {@code path} suffix stripped, or
     * {@code directory} unchanged when {@code path} is absent, {@code "."}, or
     * not a suffix of {@code directory}.
     */
    private static Path stripRelative(Path directory, String path) {
        if (path == null || path.isBlank()) {
            return directory;
        }
        Path relative = Path.of(path).normalize();
        if (relative.toString().isEmpty() || relative.toString().equals(".")) {
            return directory;
        }
        if (!directory.endsWith(relative)) {
            return directory;
        }
        Path root = directory;
        for (int i = 0; i < relative.getNameCount() && root != null; i++) {
            root = root.getParent();
        }
        return root == null ? directory : root;
    }

    /**
     * A component that could not be materialized: clone failure, nonexistent
     * branch, missing path, or a git query failure. The attempted coordinates
     * live on the {@link #plan()} and via the {@code attempted*} accessors
     * (Requirements 3.6, 5.4); the {@link #cause()} is a human-readable message
     * including the failing git output where one exists.
     */
    public record Failure(
        ComponentId component,
        SourcePlan plan,
        ResolutionReason reason,
        String cause
    ) implements Outcome {
        public Failure {
            if (component == null || plan == null || reason == null) {
                throw new IllegalArgumentException("component, plan, and reason are required");
            }
            if (cause == null || cause.isBlank()) {
                throw new IllegalArgumentException("a failure outcome requires a cause");
            }
        }

        /** The attempted repository: the clone URL, or the working tree root. */
        public String attemptedRepository() {
            return switch (plan) {
                case SourcePlan.Clone clone -> clone.url();
                case SourcePlan.WorkingTree tree -> tree.root().toString();
            };
        }

        /**
         * The attempted reference: the clone ref, or {@code null} for a working
         * tree (no reference was requested — the tree is used as checked out).
         */
        public String attemptedReference() {
            return plan instanceof SourcePlan.Clone clone ? clone.ref() : null;
        }

        /** The attempted path within the repository or working tree. */
        public String attemptedPath() {
            return switch (plan) {
                case SourcePlan.Clone clone -> clone.path();
                case SourcePlan.WorkingTree tree -> tree.path();
            };
        }
    }

    private final List<Outcome> outcomes;

    public MaterializedSources(List<Outcome> outcomes) {
        this.outcomes = List.copyOf(outcomes);
    }

    /** Every outcome, one per planned component, in plan order. */
    public List<Outcome> outcomes() {
        return outcomes;
    }

    /** The successfully materialized components, in plan order. */
    public List<Success> successes() {
        return outcomes.stream()
            .filter(Success.class::isInstance)
            .map(Success.class::cast)
            .toList();
    }

    /** The components that failed to materialize, in plan order. */
    public List<Failure> failures() {
        return outcomes.stream()
            .filter(Failure.class::isInstance)
            .map(Failure.class::cast)
            .toList();
    }

    /** Whether every planned component materialized successfully. */
    public boolean allSucceeded() {
        return failures().isEmpty();
    }

    /** The successful outcome for {@code component}, if it materialized. */
    public Optional<Success> successOf(ComponentId component) {
        return successes().stream()
            .filter(s -> s.component().equals(component))
            .findFirst();
    }

    /** The resolved directory for {@code component}, if it materialized. */
    public Optional<Path> directoryOf(ComponentId component) {
        return successOf(component).map(Success::directory);
    }
}
