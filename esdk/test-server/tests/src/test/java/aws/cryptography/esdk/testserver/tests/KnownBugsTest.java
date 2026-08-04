package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * {@link KnownBugs} ledger parsing and override resolution: the committed
 * resource loads, a valid document resolves by id, every malformed shape is
 * rejected with a message naming the problem, and per-repository overrides add
 * or remove a target — rejecting unknown, redundant, and stale overrides.
 */
class KnownBugsTest {

    private static final String LEDGER = """
        [
          {
            "id": "a",
            "description": "op does the wrong thing",
            "targets": [
              {"language": "java", "majorVersion": 3, "repository": "aws-crypto-tools-java"},
              {"language": "python", "majorVersion": 4, "repository": "aws-encryption-sdk-python"}
            ]
          },
          {
            "id": "b",
            "description": "other wrong thing",
            "targets": [
              {"language": "c", "majorVersion": 2, "repository": "aws-encryption-sdk-c"}
            ]
          }
        ]
        """;

    private static KnownBugs.Target target(String language, int majorVersion, String repository) {
        return new KnownBugs.Target(language, majorVersion, repository);
    }

    @Test
    void committedLedgerResourceLoadsAndValidates() {
        // Guards known-bugs.json itself: a malformed or invalid committed
        // ledger fails here, not mid-matrix.
        KnownBugs.shared();
    }

    @Test
    void lookupResolvesDeclaredEntriesById() {
        KnownBugs ledger = KnownBugs.parse(LEDGER);
        assertTrue(ledger.lookup("a").orElseThrow()
            .exhibitedBy(target("java", 3, "aws-crypto-tools-java")));
        assertTrue(ledger.lookup("a").orElseThrow()
            .exhibitedBy(target("python", 4, "aws-encryption-sdk-python")));
        assertTrue(ledger.lookup("b").orElseThrow()
            .exhibitedBy(target("c", 2, "aws-encryption-sdk-c")));
        assertTrue(ledger.lookup("missing").isEmpty());
        assertEquals(List.of("a", "b"), List.copyOf(ledger.ids()));
    }

    @Test
    void identityIsTheFullTriple() {
        KnownBugs ledger = KnownBugs.parse(LEDGER);
        KnownBugs.KnownBug a = ledger.lookup("a").orElseThrow();
        // Same language, different major version or repository is a different target.
        assertFalse(a.exhibitedBy(target("java", 4, "aws-crypto-tools-java")),
            "a different major version is a distinct target");
        assertFalse(a.exhibitedBy(target("java", 3, "aws-encryption-sdk")),
            "a different repository is a distinct target");
    }

    @Test
    void presentOverrideAddsATargetToABug() {
        KnownBugs ledger = KnownBugs.parse(LEDGER,
            "c:2:aws-encryption-sdk-c=+a");
        assertTrue(ledger.lookup("a").orElseThrow()
            .exhibitedBy(target("c", 2, "aws-encryption-sdk-c")));
    }

    @Test
    void absentOverrideRemovesADeclaredTarget() {
        KnownBugs ledger = KnownBugs.parse(LEDGER,
            "python:4:aws-encryption-sdk-python=-a");
        assertFalse(ledger.lookup("a").orElseThrow()
            .exhibitedBy(target("python", 4, "aws-encryption-sdk-python")));
        // The other target is untouched.
        assertTrue(ledger.lookup("a").orElseThrow()
            .exhibitedBy(target("java", 3, "aws-crypto-tools-java")));
    }

    @Test
    void overrideForUnknownBugIdIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(LEDGER, "c:2:aws-encryption-sdk-c=+nope"));
        assertTrue(e.getMessage().contains("unknown bug id 'nope'"), e.getMessage());
    }

    @Test
    void redundantPresentOverrideIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(LEDGER, "java:3:aws-crypto-tools-java=+a"));
        assertTrue(e.getMessage().contains("redundant"), e.getMessage());
    }

    @Test
    void staleAbsentOverrideIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(LEDGER, "c:2:aws-encryption-sdk-c=-a"));
        assertTrue(e.getMessage().contains("stale"), e.getMessage());
    }

    @Test
    void unsignedOverrideTokenIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(LEDGER, "java:3:aws-crypto-tools-java=a"));
        assertTrue(e.getMessage().contains("'+'"), e.getMessage());
    }

    @Test
    void malformedOverrideTargetIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(LEDGER, "java:3=+a"));
        assertTrue(e.getMessage().contains("language:major:repository"), e.getMessage());
    }

    @Test
    void nonArrayRootIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("{\"bugs\": []}"));
        assertTrue(e.getMessage().contains("must be a JSON array"), e.getMessage());
    }

    @Test
    void missingIdIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"description\": \"d\", \"targets\": "
                    + "[{\"language\": \"java\", \"majorVersion\": 3, \"repository\": \"r\"}]}]"));
        assertTrue(e.getMessage().contains("'id'"), e.getMessage());
    }

    @Test
    void blankDescriptionIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"id\": \"a\", \"description\": \" \", \"targets\": "
                    + "[{\"language\": \"java\", \"majorVersion\": 3, \"repository\": \"r\"}]}]"));
        assertTrue(e.getMessage().contains("'description'"), e.getMessage());
    }

    @Test
    void emptyTargetsIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("[{\"id\": \"a\", \"description\": \"d\", \"targets\": []}]"));
        assertTrue(e.getMessage().contains("non-empty 'targets'"), e.getMessage());
    }

    @Test
    void targetMissingMajorVersionIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"id\": \"a\", \"description\": \"d\", \"targets\": "
                    + "[{\"language\": \"java\", \"repository\": \"r\"}]}]"));
        assertTrue(e.getMessage().contains("majorVersion"), e.getMessage());
    }

    @Test
    void unknownTargetFieldIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"id\": \"a\", \"description\": \"d\", \"targets\": "
                    + "[{\"language\": \"java\", \"majorVersion\": 3, \"repository\": \"r\", \"x\": 1}]}]"));
        assertTrue(e.getMessage().contains("unknown field 'x'"), e.getMessage());
    }

    @Test
    void duplicateBugIdIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("""
                [
                  {"id": "a", "description": "d",
                   "targets": [{"language": "java", "majorVersion": 3, "repository": "r"}]},
                  {"id": "a", "description": "d2",
                   "targets": [{"language": "python", "majorVersion": 4, "repository": "r"}]}
                ]
                """));
        assertTrue(e.getMessage().contains("duplicate bug id"), e.getMessage());
    }

    @Test
    void duplicateTargetIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("""
                [{"id": "a", "description": "d", "targets": [
                  {"language": "java", "majorVersion": 3, "repository": "r"},
                  {"language": "java", "majorVersion": 3, "repository": "r"}
                ]}]
                """));
        assertTrue(e.getMessage().contains("twice"), e.getMessage());
    }

    @Test
    void unknownEntryFieldIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"id\": \"a\", \"description\": \"d\", \"targets\": "
                    + "[{\"language\": \"java\", \"majorVersion\": 3, \"repository\": \"r\"}], "
                    + "\"suites\": []}]"));
        assertTrue(e.getMessage().contains("unknown field 'suites'"), e.getMessage());
    }
}
