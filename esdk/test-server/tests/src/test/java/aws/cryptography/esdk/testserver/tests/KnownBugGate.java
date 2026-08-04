package aws.cryptography.esdk.testserver.tests;

import org.junit.jupiter.api.function.Executable;
import org.opentest4j.TestAbortedException;

/**
 * Expected-failure gate over the {@link KnownBugs} ledger, wrapped around
 * exactly the assertion a catalogued bug breaks. The assertion ALWAYS runs —
 * this is never a blind skip:
 *
 * <ul>
 *   <li>Acting target not declared for the bug: every outcome propagates
 *       unchanged — the row keeps its full power to fail.</li>
 *   <li>Declared, and the assertion fails: the row aborts as a visible skip —
 *       {@code KNOWN BUG <id>: <description> — declared for <target>} — with
 *       the assertion failure as its cause.</li>
 *   <li>Declared, and the assertion passes: the row FAILS — the ledger is
 *       stale, and the entry must be removed for that target.</li>
 * </ul>
 *
 * <p>A bug is declared against a {@code (language, majorVersion, repository)}
 * target, not a bare language, so gating keys on the acting
 * {@link LanguageServerTarget}'s full identity. Only an {@link AssertionError} is
 * attributed to the declared bug; any other throwable (transport, harness)
 * propagates unchanged. Gating on an id the ledger does not define is a test
 * failure, never a pass or a skip.
 */
public final class KnownBugGate {

    private KnownBugGate() {
    }

    /**
     * Run {@code assertion} under expected-failure semantics for {@code bugId}
     * when {@code actingTarget} — the target whose behavior the assertion checks
     * (the decryptor for a decrypt-side Test, the single target for a per-server
     * Test) — declares the bug in the ledger.
     *
     * @throws AssertionError if {@code bugId} is not in the ledger, if the
     *     declared bug did not reproduce, or (propagated) if the assertion
     *     fails for an undeclared target
     * @throws TestAbortedException visible skip when the declared bug reproduces
     */
    public static void gate(String bugId, LanguageServerTarget actingTarget, Executable assertion) {
        gate(bugId, actingTarget, assertion, KnownBugs.shared());
    }

    /**
     * Gate against an explicit ledger. Package-private so unit tests can
     * exercise the semantics without the JVM-wide singleton — mirroring
     * {@link FeatureGate#require}.
     */
    static void gate(String bugId, LanguageServerTarget actingTarget, Executable assertion,
            KnownBugs ledger) {
        KnownBugs.KnownBug bug = ledger.lookup(bugId).orElseThrow(() -> new AssertionError(
            "unknown known-bug id '" + bugId + "': the ledger " + KnownBugs.RESOURCE
                + " defines " + ledger.ids()));

        KnownBugs.Target target = new KnownBugs.Target(
            actingTarget.language(), actingTarget.majorVersion(), actingTarget.repository());
        if (!bug.exhibitedBy(target)) {
            run(assertion);
            return;
        }

        try {
            assertion.execute();
        } catch (AssertionError predicted) {
            throw new TestAbortedException(
                "KNOWN BUG " + bug.id() + ": " + bug.description()
                    + " — declared for " + target.label(),
                predicted);
        } catch (Throwable other) {
            throw sneakyThrow(other);
        }
        throw new AssertionError(
            "declared known bug did not reproduce — remove " + bug.id() + " for "
                + target.label() + " from the ledger " + KnownBugs.RESOURCE);
    }

    /** Run the assertion with every outcome propagated unchanged. */
    private static void run(Executable assertion) {
        try {
            assertion.execute();
        } catch (Throwable t) {
            throw sneakyThrow(t);
        }
    }

    /** Rethrow {@code t} as-is; {@link Executable} declares {@link Throwable}. */
    @SuppressWarnings("unchecked")
    private static <T extends Throwable> RuntimeException sneakyThrow(Throwable t) throws T {
        throw (T) t;
    }
}
