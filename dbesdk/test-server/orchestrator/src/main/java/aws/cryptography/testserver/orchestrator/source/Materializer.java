package aws.cryptography.testserver.orchestrator.source;

import java.util.List;

/**
 * Executes a run's resolution plans into {@link MaterializedSources} — the
 * seam between the pure {@link SourceResolver} planning and the git/filesystem
 * I/O. {@link SourceMaterializer} is the real implementation; the pipeline
 * tests substitute fakes so orchestration logic is exercised without cloning
 * repositories (design Testing Strategy).
 *
 * <p>Implementations capture materialization failures as
 * {@link MaterializedSources.Failure} outcomes — never exceptions — so the
 * fail-closed pipeline gate decides what a failure means (Requirement 3.6).
 */
@FunctionalInterface
public interface Materializer {

    /** Execute every plan; exactly one outcome per plan, in plan order. */
    MaterializedSources materialize(List<ResolvedComponentPlan> plans);
}
