package aws.cryptography.testserver.orchestrator.source;

/**
 * One component's resolution plan: which component, how its source is to be
 * obtained, and why that source was chosen (design "SourceResolver" output;
 * Requirements 5.1, 5.2). Produced purely by {@link SourceResolver}; executed
 * by the SourceMaterializer (task 3.1).
 *
 * @param component the component this plan resolves
 * @param plan      how to obtain the component's source
 * @param reason    why this source was chosen for the run
 */
public record ResolvedComponentPlan(
    ComponentId component,
    SourcePlan plan,
    ResolutionReason reason
) {
    public ResolvedComponentPlan {
        if (component == null) {
            throw new IllegalArgumentException("component is required");
        }
        if (plan == null) {
            throw new IllegalArgumentException("plan is required");
        }
        if (reason == null) {
            throw new IllegalArgumentException("reason is required");
        }
    }
}
