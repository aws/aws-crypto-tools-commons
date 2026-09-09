package aws.cryptography.esdk.testserver.orchestrator.source;

/**
 * Why a component's source was chosen for a run (Requirement 5.2, design
 * "Resolution_Record"). Exactly one reason applies per resolved component:
 *
 * <ul>
 *   <li>{@link #CONFIGURATION_ENTRY} — the commons-stored
 *       {@code Configuration_Entry} (or, for the commons clone itself, the
 *       {@code Commons_Configuration_Entry} branch, Requirement 4.5).</li>
 *   <li>{@link #CONFIGURATION_OVERRIDE} — a Language_Repository's
 *       {@code Configuration_Override} replaced the stored entry
 *       (Requirement 4.6).</li>
 *   <li>{@link #WORKING_TREE} — the invocation's own working tree is the
 *       active input under test ({@code Live_Source_Code}, Requirement 4.2).</li>
 *   <li>{@link #INVOCATION_OVERRIDE} — an explicit invocation-time commons
 *       branch override trumped the Commons_Configuration_Entry
 *       (Requirement 4.8).</li>
 * </ul>
 */
public enum ResolutionReason {

    CONFIGURATION_ENTRY("configuration-entry"),
    CONFIGURATION_OVERRIDE("configuration-override"),
    WORKING_TREE("working-tree"),
    INVOCATION_OVERRIDE("invocation-override");

    private final String label;

    ResolutionReason(String label) {
        this.label = label;
    }

    /** The design's canonical kebab-case label, as emitted in the Resolution_Record. */
    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}
