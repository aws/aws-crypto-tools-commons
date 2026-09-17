package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link KnownBugs} parsing of the injected per-server property: a target's set
 * of exhibited bug ids resolves by the full {@code (language, majorVersion,
 * repository)} identity, an absent target exhibits nothing, and a malformed
 * entry — a non-triple key, a non-integer major, a duplicate target, or a
 * duplicate id — is rejected (the orchestrator generates this from validated
 * configuration).
 */
class KnownBugsTest {

    private static KnownBugs.Target target(String language, int majorVersion, String repository) {
        return new KnownBugs.Target(language, majorVersion, repository);
    }

    @Test
    void parsesPerServerSets() {
        KnownBugs bugs = KnownBugs.parse(
            "java:3:aws-crypto-tools-java=a;b,c:2:aws-encryption-sdk-c=x");
        assertTrue(bugs.exhibits(target("java", 3, "aws-crypto-tools-java"), "a"));
        assertTrue(bugs.exhibits(target("java", 3, "aws-crypto-tools-java"), "b"));
        assertTrue(bugs.exhibits(target("c", 2, "aws-encryption-sdk-c"), "x"));
        assertFalse(bugs.exhibits(target("java", 3, "aws-crypto-tools-java"), "x"),
            "a target exhibits only its own declared ids");
        assertEquals(Set.of("a", "b"),
            bugs.bugsFor(target("java", 3, "aws-crypto-tools-java")));
    }

    @Test
    void blankOrAbsentIsNoBugs() {
        assertTrue(KnownBugs.parse(null).bugsFor(target("java", 3, "r")).isEmpty());
        assertTrue(KnownBugs.parse("   ").bugsFor(target("java", 3, "r")).isEmpty());
    }

    @Test
    void absentTargetExhibitsNothing() {
        KnownBugs bugs = KnownBugs.parse("java:3:aws-crypto-tools-java=a");
        assertFalse(bugs.exhibits(target("python", 4, "aws-encryption-sdk-python"), "a"));
        assertTrue(bugs.bugsFor(target("python", 4, "aws-encryption-sdk-python")).isEmpty());
    }

    @Test
    void identityIsTheFullTriple() {
        KnownBugs bugs = KnownBugs.parse("java:3:aws-crypto-tools-java=a");
        assertFalse(bugs.exhibits(target("java", 4, "aws-crypto-tools-java"), "a"),
            "a different major version is a distinct target");
        assertFalse(bugs.exhibits(target("java", 3, "aws-encryption-sdk"), "a"),
            "a different repository is a distinct target");
    }

    @Test
    void nonTripleKeyIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("java:3=a"));
        assertTrue(e.getMessage().contains("language:major:repository"), e.getMessage());
    }

    @Test
    void nonIntegerMajorIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("java:x:aws-crypto-tools-java=a"));
        assertTrue(e.getMessage().contains("not an integer"), e.getMessage());
    }

    @Test
    void duplicateTargetIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "java:3:aws-crypto-tools-java=a,java:3:aws-crypto-tools-java=b"));
        assertTrue(e.getMessage().contains("duplicate target"), e.getMessage());
    }

    @Test
    void duplicateIdWithinTargetIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("java:3:aws-crypto-tools-java=a;a"));
        assertTrue(e.getMessage().contains("duplicate bug id"), e.getMessage());
    }
}
