package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.List;

/**
 * The outcome of validating a {@link ConfigurationSet} (Requirement 9.5,
 * Property 11). When {@link #valid()} is {@code false}, {@link #errors()} lists
 * one message per problem, each identifying the offending entry so no server is
 * started for an invalid set.
 *
 * @param valid  {@code true} iff every entry is well-formed and ports are unique
 * @param errors the problems found (empty iff {@code valid})
 */
public record ConfigurationSetValidation(boolean valid, List<String> errors) {

    public ConfigurationSetValidation {
        errors = List.copyOf(errors);
    }

    /** @return a single joined error message (for aborting a run). */
    public String message() {
        return String.join("; ", errors);
    }
}
