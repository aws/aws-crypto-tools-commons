package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

/**
 * {@link KnownBugGate} expected-failure semantics against an explicit ledger:
 * a declared, reproducing bug becomes an attributed skip; a declared bug that
 * does not reproduce fails the row; an undeclared target's assertion runs with
 * every outcome untouched. Declaration keys on the full
 * {@code (language, majorVersion, repository)} identity.
 */
class KnownBugGateTest {

    private static final KnownBugs LEDGER = KnownBugs.parse("""
        [
          {
            "id": "decrypt-accepts-garbage",
            "description": "decrypt accepts garbage",
            "targets": [
              {"language": "java", "majorVersion": 3, "repository": "aws-crypto-tools-java"}
            ]
          }
        ]
        """);

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
            }, LEDGER));
        assertEquals("KNOWN BUG decrypt-accepts-garbage: decrypt accepts garbage "
                + "— declared for java-v3 in aws-crypto-tools-java",
            skip.getMessage());
        assertSame(predicted, skip.getCause(),
            "the skip must carry the underlying assertion failure as its cause");
    }

    @Test
    void declaredBugThatDoesNotReproduceFailsTheRow() {
        AssertionError stale = assertThrows(AssertionError.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage", JAVA, () -> {
            }, LEDGER));
        assertEquals("declared known bug did not reproduce — remove decrypt-accepts-garbage for "
                + "java-v3 in aws-crypto-tools-java from the ledger " + KnownBugs.RESOURCE,
            stale.getMessage());
    }

    @Test
    void undeclaredTargetFailurePropagatesUnchanged() {
        AssertionError genuine = new AssertionError("a new finding");
        AssertionError propagated = assertThrows(AssertionError.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage",
                target("python", 4, "aws-encryption-sdk-python"), () -> {
                    throw genuine;
                }, LEDGER));
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
                }, LEDGER));
        assertSame(genuine, propagated);
    }

    @Test
    void undeclaredTargetPassingAssertionPasses() {
        AtomicBoolean ran = new AtomicBoolean();
        KnownBugGate.gate("decrypt-accepts-garbage",
            target("python", 4, "aws-encryption-sdk-python"), () -> ran.set(true), LEDGER);
        assertTrue(ran.get(), "the assertion must run for an undeclared target");
    }

    @Test
    void unknownBugIdFailsWithoutRunningTheAssertion() {
        AtomicBoolean ran = new AtomicBoolean();
        AssertionError unknown = assertThrows(AssertionError.class,
            () -> KnownBugGate.gate("not-in-the-ledger", JAVA, () -> ran.set(true), LEDGER));
        assertTrue(unknown.getMessage().contains("unknown known-bug id 'not-in-the-ledger'"),
            unknown.getMessage());
        assertTrue(unknown.getMessage().contains("decrypt-accepts-garbage"),
            "the failure must list the ids the ledger does define: " + unknown.getMessage());
        assertFalse(ran.get(), "an unknown id must fail before the assertion runs");
    }

    @Test
    void nonAssertionThrowableIsNotAttributedToTheBug() {
        IllegalStateException transport = new IllegalStateException("connection reset");
        IllegalStateException propagated = assertThrows(IllegalStateException.class,
            () -> KnownBugGate.gate("decrypt-accepts-garbage", JAVA, () -> {
                throw transport;
            }, LEDGER));
        assertSame(transport, propagated,
            "only an AssertionError is the declared bug's signature");
    }
}
