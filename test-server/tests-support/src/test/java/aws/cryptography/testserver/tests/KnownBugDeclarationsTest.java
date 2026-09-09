package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

/**
 * {@link KnownBugDeclarations} parsing + {@link KnownBugGate#gateDeclared} over
 * the injected known-bug registry ({@code testserver.knownBugs}): a declared,
 * reproducing bug becomes an attributed skip; a declared bug that does not
 * reproduce fails the row; a language (or registry) that does not declare the
 * bug runs the assertion with every outcome untouched.
 */
class KnownBugDeclarationsTest {

    @Test
    void absentRegistryExhibitsNothing() {
        KnownBugDeclarations empty = KnownBugDeclarations.parse(null);
        assertFalse(empty.exhibits("java", "any-bug"));
        assertFalse(KnownBugDeclarations.parse("  ").exhibits("rust", "any-bug"));
    }

    @Test
    void parsesPerLanguageBugIds() {
        KnownBugDeclarations d = KnownBugDeclarations.parse("java:bug-a;bug-b,rust:bug-a");
        assertTrue(d.exhibits("java", "bug-a"));
        assertTrue(d.exhibits("java", "bug-b"));
        assertTrue(d.exhibits("rust", "bug-a"));
        assertFalse(d.exhibits("rust", "bug-b"), "rust does not declare bug-b");
        assertFalse(d.exhibits("net", "bug-a"), "net declares nothing");
    }

    @Test
    void rejectsMalformedEntries() {
        assertThrows(IllegalArgumentException.class, () -> KnownBugDeclarations.parse("nocolon"));
        assertThrows(IllegalArgumentException.class, () -> KnownBugDeclarations.parse(":bug"));
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:bug-a,java:bug-b"), "duplicate language");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:bug-a;bug-a"), "duplicate id");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:"), "no ids");
    }

    @Test
    void declaredBugThatReproducesSkipsWithAttribution() {
        KnownBugDeclarations d = KnownBugDeclarations.parse("java:decrypt-accepts-garbage");
        AssertionError predicted = new AssertionError("decrypt did not reject");
        TestAbortedException skip = assertThrows(TestAbortedException.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", "java", () -> {
                throw predicted;
            }, d));
        assertEquals("KNOWN BUG decrypt-accepts-garbage — declared for java", skip.getMessage());
        assertSame(predicted, skip.getCause());
    }

    @Test
    void declaredBugThatDoesNotReproduceFailsTheRow() {
        KnownBugDeclarations d = KnownBugDeclarations.parse("java:decrypt-accepts-garbage");
        assertThrows(AssertionError.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", "java", () -> {
                // asserts correct behavior — the bug did not reproduce
            }, d));
    }

    @Test
    void undeclaredLanguageRunsAssertionUnchanged() {
        KnownBugDeclarations d = KnownBugDeclarations.parse("java:decrypt-accepts-garbage");
        // rust does not declare the bug: a failing assertion propagates as a real failure.
        AssertionError failure = new AssertionError("rust must reject");
        AssertionError propagated = assertThrows(AssertionError.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", "rust", () -> {
                throw failure;
            }, d));
        assertSame(failure, propagated);
    }
}
