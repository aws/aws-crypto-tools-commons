package aws.cryptography.testserver.tests;

import org.junit.jupiter.api.function.Executable;
import org.opentest4j.TestAbortedException;

/**
 * Expected-failure gate over the {@link KnownBugs} ledger, wrapped around
 * exactly the assertion a catalogued bug breaks. The assertion ALWAYS runs —
 * this is never a blind skip:
 *
 * <ul>
 *   <li>Acting language not declared for the bug: every outcome propagates
 *       unchanged — the row keeps its full power to fail.</li>
 *   <li>Declared, and the assertion fails: the row aborts as a visible skip —
 *       {@code KNOWN BUG <id>: <description> — declared for <language>} — with
 *       the assertion failure as its cause.</li>
 *   <li>Declared, and the assertion passes: the row FAILS — the ledger is
 *       stale, and the entry must be removed for that language.</li>
 * </ul>
 *
 * <p>Only an {@link AssertionError} is attributed to the declared bug; any
 * other throwable (transport, harness) propagates unchanged. Gating on an id
 * the ledger does not define is a test failure, never a pass or a skip.
 */
public final class KnownBugGate {

    private KnownBugGate() {
    }

    /**
     * Run {@code assertion} under expected-failure semantics for {@code bugId}
     * when {@code actingLanguage} — the language whose behavior the assertion
     * checks (the decryptor for a decrypt-side Test, the single target for a
     * per-server Test) — declares the bug in the ledger.
     *
     * @throws AssertionError if {@code bugId} is not in the ledger, if the
     *     declared bug did not reproduce, or (propagated) if the assertion
     *     fails for an undeclared language
     * @throws TestAbortedException visible skip when the declared bug reproduces
     */
    public static void gate(String bugId, String actingLanguage, Executable assertion) {
        gate(bugId, actingLanguage, assertion, KnownBugs.shared());
    }

    /**
     * Gate against an explicit ledger. Package-private so unit tests can
     * exercise the semantics without the JVM-wide singleton — mirroring
     * {@link FeatureGate#require}.
     */
    static void gate(String bugId, String actingLanguage, Executable assertion, KnownBugs ledger) {
        KnownBugs.KnownBug bug = ledger.lookup(bugId).orElseThrow(() -> new AssertionError(
            "unknown known-bug id '" + bugId + "': the ledger " + KnownBugs.RESOURCE
                + " defines " + ledger.ids()));

        if (!bug.exhibitedBy(actingLanguage)) {
            run(assertion);
            return;
        }

        try {
            assertion.execute();
        } catch (AssertionError predicted) {
            throw new TestAbortedException(
                "KNOWN BUG " + bug.id() + ": " + bug.description()
                    + " — declared for " + actingLanguage,
                predicted);
        } catch (Throwable other) {
            throw sneakyThrow(other);
        }
        throw new AssertionError(
            "declared known bug did not reproduce — remove " + bug.id() + " for "
                + actingLanguage + " from the ledger " + KnownBugs.RESOURCE);
    }

    /**
     * Run {@code assertion} under expected-failure semantics for {@code bugId}
     * when {@code actingLanguage} declares it in the injected
     * {@link KnownBugDeclarations} registry ({@code testserver.knownBugs}) — the
     * injection-based counterpart to {@link #gate(String, String, Executable)},
     * for products whose bug ledger is per-server config rather than a classpath
     * ledger. When the acting language does not declare the bug, every outcome
     * propagates unchanged (the row keeps its full power to fail).
     *
     * @throws AssertionError if the declared bug did not reproduce (stale — the
     *     server's {@code bug-config.json} entry must be removed), or
     *     (propagated) if the assertion fails for a language that does not
     *     declare the bug
     * @throws TestAbortedException visible skip when the declared bug reproduces
     */
    public static void gateDeclared(String bugId, String actingLanguage, Executable assertion) {
        gateDeclared(bugId, actingLanguage, assertion, KnownBugDeclarations.shared());
    }

    /** Injected-registry gate against an explicit registry; package-private for unit tests. */
    static void gateDeclared(String bugId, String actingLanguage, Executable assertion,
            KnownBugDeclarations declarations) {
        if (!declarations.exhibits(actingLanguage, bugId)) {
            run(assertion);
            return;
        }
        try {
            assertion.execute();
        } catch (AssertionError predicted) {
            throw new TestAbortedException(
                "KNOWN BUG " + bugId + " — declared for " + actingLanguage, predicted);
        } catch (Throwable other) {
            throw sneakyThrow(other);
        }
        throw new AssertionError(
            "declared known bug did not reproduce — remove '" + bugId + "' for "
                + actingLanguage + " from its bug-config.json");
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
