package aws.cryptography.esdk.testserver.orchestrator.source;

import java.util.Map;
import java.util.Optional;

/**
 * The outcome of {@link SourceResolver#resolve}: either a per-language mapping to
 * its effective {@link ResolvedSource} (Property 12), or a failure describing why
 * the run must abort before any {@code Tests} run (Property 13, Requirements
 * 11.5, 12.9).
 */
public final class SourceResolution {

    private final Map<String, ResolvedSource> resolved;
    private final String failure;

    private SourceResolution(Map<String, ResolvedSource> resolved, String failure) {
        this.resolved = resolved;
        this.failure = failure;
    }

    static SourceResolution resolved(Map<String, ResolvedSource> resolved) {
        return new SourceResolution(Map.copyOf(resolved), null);
    }

    static SourceResolution failed(String failure) {
        return new SourceResolution(Map.of(), failure);
    }

    /** @return {@code true} when every language mapped to a single effective source. */
    public boolean isResolved() {
        return failure == null;
    }

    /** @return the reason the run must abort, when {@link #isResolved()} is false. */
    public Optional<String> failure() {
        return Optional.ofNullable(failure);
    }

    /** @return the per-language effective source (empty when {@link #isResolved()} is false). */
    public Map<String, ResolvedSource> sources() {
        return resolved;
    }
}
