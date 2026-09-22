package aws.cryptography.testserver.tests;

import org.junit.jupiter.api.function.Executable;
import org.opentest4j.TestAbortedException;

/**
 * Expected-failure gate over the injected {@link KnownBugDeclarations} registry
 * ({@code testserver.knownBugs}, flattened from each server's
 * {@code bug-config.json}), wrapped around exactly the assertion a catalogued
 * bug breaks. The assertion ALWAYS runs — this is never a blind skip:
 *
 * <ul>
 *   <li>Acting target not declared for the bug: every outcome propagates
 *       unchanged — the row keeps its full power to fail.</li>
 *   <li>Declared, and the assertion fails: the row aborts as a visible skip —
 *       {@code KNOWN BUG <id> — declared for <target>} — with the assertion
 *       failure as its cause.</li>
 *   <li>Declared, and the assertion passes: the row FAILS — the declaration is
 *       stale, and the entry must be removed for that target.</li>
 * </ul>
 *
 * <p>Only an {@link AssertionError} is attributed to the declared bug; any
 * other throwable (transport, harness) propagates unchanged.
 */
public final class KnownBugGate {

    private KnownBugGate() {
    }

    /**
     * Run {@code assertion} under expected-failure semantics for {@code bugId}
     * when {@code actingTarget} — the source whose behavior the assertion checks
     * (the decryptor for a decrypt-side Test, the single target for a per-server
     * Test) — declares it in the injected {@link KnownBugDeclarations} registry
     * ({@code testserver.knownBugs}), flattened from each server's
     * {@code bug-config.json} and keyed by the full {@code (language,
     * majorVersion, repo)} source identity. When the acting target does not
     * declare the bug, every outcome propagates unchanged (the row keeps its
     * full power to fail).
     *
     * @throws AssertionError if the declared bug did not reproduce (stale — the
     *     server's {@code bug-config.json} entry must be removed), or
     *     (propagated) if the assertion fails for a target that does not declare
     *     the bug
     * @throws TestAbortedException visible skip when the declared bug reproduces
     */
    public static void gateDeclared(String bugId, LanguageServerTarget actingTarget,
            Executable assertion) {
        gateDeclared(bugId, actingTarget, assertion, KnownBugDeclarations.shared());
    }

    /** Injected-registry gate against an explicit registry; package-private for unit tests. */
    static void gateDeclared(String bugId, LanguageServerTarget actingTarget, Executable assertion,
            KnownBugDeclarations declarations) {
        if (!declarations.exhibits(actingTarget.language(), actingTarget.majorVersion(),
                actingTarget.repo(), bugId)) {
            run(assertion);
            return;
        }
        try {
            assertion.execute();
        } catch (AssertionError predicted) {
            throw new TestAbortedException(
                "KNOWN BUG " + bugId + " — declared for " + actingTarget.label(), predicted);
        } catch (Throwable other) {
            throw sneakyThrow(other);
        }
        throw new AssertionError(
            "declared known bug did not reproduce — remove '" + bugId + "' for "
                + actingTarget.label() + " from its bug-config.json");
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
