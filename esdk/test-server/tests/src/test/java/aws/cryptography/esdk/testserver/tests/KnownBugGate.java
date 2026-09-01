package aws.cryptography.esdk.testserver.tests;

import org.junit.jupiter.api.function.Executable;
import org.opentest4j.TestAbortedException;

/**
 * Expected-failure gate over the per-server {@link KnownBugs} sets, wrapped
 * around exactly the assertion a catalogued bug breaks. The assertion ALWAYS
 * runs — this is never a blind skip:
 *
 * <ul>
 *   <li>Acting target does not declare the bug: every outcome propagates
 *       unchanged — the row keeps its full power to fail.</li>
 *   <li>Declared, and the assertion fails: the row aborts as a visible skip —
 *       {@code KNOWN BUG <id> — declared for <target>} — with the assertion
 *       failure as its cause.</li>
 *   <li>Declared, and the assertion passes: the row FAILS — the declaration is
 *       stale, and the id must be removed from that server's
 *       {@code bug-configuration.json}.</li>
 * </ul>
 *
 * <p>A bug is declared against a {@code (language, majorVersion, repository)}
 * target, not a bare language, so gating keys on the acting
 * {@link LanguageServerTarget}'s full identity. Only an {@link AssertionError} is
 * attributed to the declared bug; any other throwable (transport, harness)
 * propagates unchanged. There is no central catalogue of ids, so an id no server
 * declares simply means every target asserts live — a fully-fixed bug's rows
 * pass everywhere with nothing to remove.
 */
public final class KnownBugGate {

    private KnownBugGate() {
    }

    /**
     * Run {@code assertion} under expected-failure semantics for {@code bugId}
     * when {@code actingTarget} — the target whose behavior the assertion checks
     * (the decryptor for a decrypt-side Test, the single target for a per-server
     * Test) — declares the bug in its own {@code bug-configuration.json}.
     *
     * @throws AssertionError if the declared bug did not reproduce, or
     *     (propagated) if the assertion fails for a target that does not declare it
     * @throws TestAbortedException visible skip when the declared bug reproduces
     */
    public static void gate(String bugId, LanguageServerTarget actingTarget, Executable assertion) {
        gate(bugId, actingTarget, assertion, KnownBugs.shared());
    }

    /**
     * Gate against explicit per-server sets. Package-private so unit tests can
     * exercise the semantics without the JVM-wide singleton — mirroring
     * {@link FeatureGate#require}.
     */
    static void gate(String bugId, LanguageServerTarget actingTarget, Executable assertion,
            KnownBugs bugs) {
        KnownBugs.Target target = new KnownBugs.Target(
            actingTarget.language(), actingTarget.majorVersion(), actingTarget.repository());
        if (!bugs.exhibits(target, bugId)) {
            run(assertion);
            return;
        }

        try {
            assertion.execute();
        } catch (AssertionError predicted) {
            throw new TestAbortedException(
                "KNOWN BUG " + bugId + " — declared for " + target.label(), predicted);
        } catch (Throwable other) {
            throw sneakyThrow(other);
        }
        throw new AssertionError(
            "declared known bug did not reproduce — remove " + bugId + " for "
                + target.label() + " from its bug-configuration.json");
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
