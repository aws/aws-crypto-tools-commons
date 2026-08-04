package aws.cryptography.esdk.testserver.orchestrator.config;

import java.util.List;

/**
 * A Language_Repository's override of the commons base known-bug ledger for its
 * OWN Language_Server target, carried in the repository's commons-configuration
 * file under {@code knownBugOverrides} (the known-bug analogue of the
 * {@code supportedFeatures} / {@code unsupportedFeatures} Feature_Declaration).
 *
 * <ul>
 *   <li>{@code present}: bug ids this target exhibits that the base ledger did
 *       not record for it — the target is added to those bugs.</li>
 *   <li>{@code absent}: base-declared bug ids this target no longer exhibits —
 *       the target is removed from those bugs. This is the "PR the exception
 *       away, watch the row go red, then fix it green" lever.</li>
 * </ul>
 *
 * <p>Fields are deliberately nullable so an under-specified object is
 * representable and rejected by validation naming each problem, rather than
 * failing to parse. A {@code null} array means the array was absent from the
 * JSON.
 *
 * @param present bug ids to add to this target, or {@code null} when absent
 * @param absent  bug ids to remove from this target, or {@code null} when absent
 */
public record KnownBugOverride(List<String> present, List<String> absent) {
    public KnownBugOverride {
        present = present == null ? null : List.copyOf(present);
        absent = absent == null ? null : List.copyOf(absent);
    }

    /** @return true iff neither half declares anything (a no-op override). */
    public boolean isEmpty() {
        return (present == null || present.isEmpty()) && (absent == null || absent.isEmpty());
    }
}
