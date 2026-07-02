package aws.cryptography.esdk.testserver.orchestrator.source;

import java.nio.file.Path;

/**
 * A per-language consumption override supplied at invocation time (design
 * "Source Resolution Inputs", Requirements 11, 12). Each variant names the
 * language it applies to. When no override is given for a language it defaults to
 * the head of its configured branch/repository (Requirement 10.1).
 *
 * <p>Per language, at most one of {@code Live}/{@code Submodule}/{@code Artifact}
 * (plus the implicit head default) may apply; specifying more than one is a hard
 * error (Requirement 12.9). {@code Live} may apply to at most one language across
 * the whole invocation (Requirement 11.5).
 */
public sealed interface Override
    permits Override.Live, Override.Submodule, Override.Artifact {

    /** The language this override applies to (logical key, e.g. {@code "java"}). */
    String language();

    /** Live working-tree source for the language under active development (Req 11.1). */
    record Live(String language, Path path) implements Override {
    }

    /** A submodule reference pinned to a specific commit (Req 12.2, 12.4). */
    record Submodule(String language, String commit) implements Override {
    }

    /** A published, versioned packaged artifact (Req 12.3, 12.7). */
    record Artifact(String language, String version) implements Override {
    }
}
