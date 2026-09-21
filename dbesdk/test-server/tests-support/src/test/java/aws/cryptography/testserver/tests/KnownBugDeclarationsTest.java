package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

/**
 * {@link KnownBugDeclarations} parsing — keyed by the full {@code (language,
 * majorVersion, repo)} source identity — plus {@link KnownBugGate#gateDeclared}
 * over the injected registry: a declared, reproducing bug becomes an attributed
 * skip; a declared bug that does not reproduce fails the row; a target (or
 * registry) that does not declare the bug runs the assertion with every outcome
 * untouched; only an {@link AssertionError} is attributed to the declared bug.
 */
class KnownBugDeclarationsTest {

    private static final String REPO = "aws-database-encryption-sdk-dynamodb";

    private static LanguageServerTarget target(String language, int major) {
        return new LanguageServerTarget(
            language, major, REPO, URI.create("http://127.0.0.1:0/" + language));
    }

    @Test
    void absentRegistryExhibitsNothing() {
        assertFalse(KnownBugDeclarations.parse(null).exhibits("java", 3, REPO, "any-bug"));
        assertFalse(KnownBugDeclarations.parse("  ").exhibits("rust", 1, REPO, "any-bug"));
    }

    @Test
    void parsesPerSourceBugIds() {
        KnownBugDeclarations d = KnownBugDeclarations.parse(
            "java:3:" + REPO + "=bug-a;bug-b,rust:1:" + REPO + "=bug-a");
        assertTrue(d.exhibits("java", 3, REPO, "bug-a"));
        assertTrue(d.exhibits("java", 3, REPO, "bug-b"));
        assertTrue(d.exhibits("rust", 1, REPO, "bug-a"));
        assertFalse(d.exhibits("rust", 1, REPO, "bug-b"), "rust does not declare bug-b");
        assertFalse(d.exhibits("net", 4, REPO, "bug-a"), "net declares nothing");
    }

    @Test
    void distinguishesByMajorVersionAndRepo() {
        KnownBugDeclarations d = KnownBugDeclarations.parse("java:3:" + REPO + "=only-v3");
        assertTrue(d.exhibits("java", 3, REPO, "only-v3"));
        assertFalse(d.exhibits("java", 2, REPO, "only-v3"),
            "a different major version is a different source");
        assertFalse(d.exhibits("java", 3, "other-repo", "only-v3"),
            "a different repo is a different source");
    }

    @Test
    void rejectsMalformedEntries() {
        assertThrows(IllegalArgumentException.class, () -> KnownBugDeclarations.parse("noequals"));
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:3=bug"), "missing repo segment");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse(":3:" + REPO + "=bug"), "blank language");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:x:" + REPO + "=bug"), "non-integer major");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:3:" + REPO + "=bug-a,java:3:" + REPO + "=bug-b"),
            "duplicate target");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:3:" + REPO + "=bug-a;bug-a"), "duplicate id");
        assertThrows(IllegalArgumentException.class,
            () -> KnownBugDeclarations.parse("java:3:" + REPO + "="), "no ids");
    }

    @Test
    void declaredBugThatReproducesSkipsWithAttribution() {
        KnownBugDeclarations d =
            KnownBugDeclarations.parse("java:3:" + REPO + "=decrypt-accepts-garbage");
        AssertionError predicted = new AssertionError("decrypt did not reject");
        TestAbortedException skip = assertThrows(TestAbortedException.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", target("java", 3), () -> {
                throw predicted;
            }, d));
        assertEquals("KNOWN BUG decrypt-accepts-garbage — declared for java-v3", skip.getMessage());
        assertSame(predicted, skip.getCause());
    }

    @Test
    void declaredBugThatDoesNotReproduceFailsTheRow() {
        KnownBugDeclarations d =
            KnownBugDeclarations.parse("java:3:" + REPO + "=decrypt-accepts-garbage");
        assertThrows(AssertionError.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", target("java", 3), () -> {
                // asserts correct behavior — the bug did not reproduce
            }, d));
    }

    @Test
    void undeclaredTargetRunsAssertionUnchanged() {
        KnownBugDeclarations d =
            KnownBugDeclarations.parse("java:3:" + REPO + "=decrypt-accepts-garbage");
        // rust does not declare the bug: a failing assertion propagates as a real failure.
        AssertionError failure = new AssertionError("rust must reject");
        AssertionError propagated = assertThrows(AssertionError.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", target("rust", 1), () -> {
                throw failure;
            }, d));
        assertSame(failure, propagated);
    }

    @Test
    void nonAssertionThrowableIsNotAttributedToTheBug() {
        KnownBugDeclarations d =
            KnownBugDeclarations.parse("java:3:" + REPO + "=decrypt-accepts-garbage");
        IllegalStateException transport = new IllegalStateException("connection reset");
        IllegalStateException propagated = assertThrows(IllegalStateException.class,
            () -> KnownBugGate.gateDeclared("decrypt-accepts-garbage", target("java", 3), () -> {
                throw transport;
            }, d));
        assertSame(transport, propagated, "only an AssertionError is the declared bug's signature");
    }
}
