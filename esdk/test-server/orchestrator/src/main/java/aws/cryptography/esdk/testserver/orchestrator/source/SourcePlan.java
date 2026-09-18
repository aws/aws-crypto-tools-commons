package aws.cryptography.esdk.testserver.orchestrator.source;

import java.nio.file.Path;

/**
 * How a component's source is to be obtained — the plan half of a
 * {@link ResolvedComponentPlan}. Planning is pure (design "SourceResolver");
 * executing a plan (cloning, path checks, commit identification) is the
 * SourceMaterializer's job (task 3.1).
 */
public sealed interface SourcePlan permits SourcePlan.Clone, SourcePlan.WorkingTree {

    /**
     * Obtain the repository by cloning at exactly {@code (url, ref)} and use
     * the component at {@code path} within the clone (Requirement 3.3).
     *
     * @param url  the clone URL
     * @param ref  the reference (branch) to obtain the repository at
     * @param path the component directory relative to the repository root
     */
    record Clone(String url, String ref, String path) implements SourcePlan {
    }

    /**
     * Use the component at {@code path} within an already-present working tree
     * rooted at {@code root} — no clone, any configured ref ignored
     * (Requirements 3.4, 4.2).
     *
     * @param root the working tree root
     * @param path the component directory relative to {@code root}
     */
    record WorkingTree(Path root, String path) implements SourcePlan {
    }
}
