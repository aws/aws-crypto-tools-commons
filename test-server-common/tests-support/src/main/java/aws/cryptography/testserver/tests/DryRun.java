package aws.cryptography.testserver.tests;

import java.util.List;
import org.opentest4j.TestAbortedException;

/**
 * A dry run lists which tests would run for a language without starting any
 * Language_Server. Every skip a test can take before its first server call
 * (the {@link FeatureGate}, a keyring negotiation) still happens; a test that
 * gets as far as building a client stops there and is logged as
 * {@value #WOULD_RUN} in the {@link FeatureGateLog}.
 *
 * <p>The log, not the JUnit result, is the record: a stop inside
 * {@code assertThrows} or a jqwik property is reported as a failure or a
 * rejection.
 */
public final class DryRun {

    /** System property that turns a dry run on. */
    public static final String PROPERTY = "testserver.dryRun";

    /** The {@link FeatureGateLog} result and abort message for a test that would run. */
    public static final String WOULD_RUN = "would-run";

    private DryRun() {
    }

    public static boolean enabled() {
        return Boolean.getBoolean(PROPERTY);
    }

    /** Log the running test as one that would run, then stop it. */
    static void stopAsWouldRun() {
        FeatureGateLog.record(List.of(), List.of(), WOULD_RUN);
        throw new TestAbortedException(WOULD_RUN);
    }
}
