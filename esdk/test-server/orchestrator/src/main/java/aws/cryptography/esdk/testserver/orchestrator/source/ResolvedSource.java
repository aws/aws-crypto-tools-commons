package aws.cryptography.esdk.testserver.orchestrator.source;

import java.nio.file.Path;

/**
 * The single effective source a language resolves to for one invocation (design
 * "Source Resolution and Build Strategy"). Exactly one of the four modes applies
 * per language (Requirement 12.9): the three explicit overrides, or the
 * head-of-branch default (Requirement 10.1).
 */
public sealed interface ResolvedSource
    permits ResolvedSource.Live, ResolvedSource.Submodule,
            ResolvedSource.Artifact, ResolvedSource.Head {

    /** Build from a provided working tree (Req 11.1, 11.2). */
    record Live(Path path) implements ResolvedSource {
    }

    /** Build from a pinned commit checked out as a submodule (Req 12.2, 12.4). */
    record Submodule(String commit) implements ResolvedSource {
    }

    /** Consume a published artifact without rebuilding (Req 12.3, 12.7). */
    record Artifact(String version) implements ResolvedSource {
    }

    /** Default: build from the head of the configured branch/repository (Req 10.1, 10.2). */
    record Head(String branch, String repository) implements ResolvedSource {
    }
}
