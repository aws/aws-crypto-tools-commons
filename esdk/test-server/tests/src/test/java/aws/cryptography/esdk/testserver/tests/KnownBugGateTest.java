package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

/**
 * {@link KnownBugGate} expected-failure semantics against explicit per-server
 * sets: a declared, reproducing bug becomes an attributed skip; a declared bug
 * that does not reproduce fails the row; a target that does not declare the bug
 * runs its assertion with every outcome untouched. Declaration keys on the full
 * {@code (language, majorVersion, repository)} identity, and there is no central
 * catalogue — an id no target declares simply runs live.
 */
class KnownBugGateTest {

    private static final KnownBugs BUGS = KnownBugs.parse(
        "java:3:aws-crypto-tools-java=decrypt-accepts-garbage");

    private static LanguageServerTarget target(String language, int majorVersion, String repository) {
        return new LanguageServerTarget(
            language, majorVersion, repository, URI.create("http://127.0.0.1:0/" + language));
    }

    private static final LanguageServerTarget JAVA = target("java", 3, "aws-crypto-tools-java");

    @Test
    void declaredBugThatReproducesSkipsWithAttribution() {
        AssertionError predicted = new AssertionError("decrypt did not reject");
        TestAbortedException skip = assertThrows(TestAbortedException.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage", JAVA, () -> {
                throw predicted;
            }, BUGS));
        assertEquals("KNOWN BUG decrypt-accepts-garbage "
                + "— declared for java-v3 in aws-crypto-tools-java",
            skip.getMessage());
        assertSame(predicted, skip.getCause(),
            "the skip must carry the underlying assertion failure as its cause");
    }

    @Test
    void declaredBugThatDoesNotReproduceFailsTheRow() {
        AssertionError stale = assertThrows(AssertionError.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage", JAVA, () -> {
            }, BUGS));
        assertEquals("declared known bug did not reproduce — remove decrypt-accepts-garbage for "
                + "java-v3 in aws-crypto-tools-java from its bug-config.json",
            stale.getMessage());
    }

    @Test
    void undeclaredTargetFailurePropagatesUnchanged() {
        AssertionError genuine = new AssertionError("a new finding");
        AssertionError propagated = assertThrows(AssertionError.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage",
                target("python", 4, "aws-encryption-sdk-python"), () -> {
                    throw genuine;
                }, BUGS));
        assertSame(genuine, propagated);
    }

    @Test
    void sameLanguageDifferentRepositoryIsUndeclared() {
        // The bug is declared for java in aws-crypto-tools-java only; a java
        // server from another repository must keep its full power to fail.
        AssertionError genuine = new AssertionError("a finding in another java repo");
        AssertionError propagated = assertThrows(AssertionError.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage",
                target("java", 3, "aws-encryption-sdk"), () -> {
                    throw genuine;
                }, BUGS));
        assertSame(genuine, propagated);
    }

    @Test
    void undeclaredTargetPassingAssertionPasses() {
        AtomicBoolean ran = new AtomicBoolean();
        KnownBugGate.gate("decrypt-accepts-garbage",
            target("python", 4, "aws-encryption-sdk-python"), () -> ran.set(true), BUGS);
        assertTrue(ran.get(), "the assertion must run for a target that does not declare the bug");
    }

    @Test
    void idNoTargetDeclaresRunsLive() {
        // With no central catalogue, an id the acting target does not declare is
        // not an error — the assertion simply runs live and its outcome stands.
        AtomicBoolean ran = new AtomicBoolean();
        KnownBugGate.gate("some-other-bug", JAVA, () -> ran.set(true), BUGS);
        assertTrue(ran.get(), "an id the target does not declare runs live");
    }

    @Test
    void nonAssertionThrowableIsNotAttributedToTheBug() {
        IllegalStateException transport = new IllegalStateException("connection reset");
        IllegalStateException propagated = assertThrows(IllegalStateException.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage", JAVA, () -> {
                throw transport;
            }, BUGS));
        assertSame(transport, propagated,
            "only an AssertionError is the declared bug's signature");
    }
}
