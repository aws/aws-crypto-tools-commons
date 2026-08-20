package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * {@link KnownBugs} ledger parsing: the committed resource loads, a valid
 * document resolves by id, and every malformed shape is rejected with a
 * message naming the problem.
 */
class KnownBugsTest {

    @Test
    void lookupResolvesDeclaredEntriesById() {
        KnownBugs ledger = KnownBugs.parse("""
            [
              {"id": "a", "description": "op does the wrong thing", "languages": ["java", "python"]},
              {"id": "b", "description": "other wrong thing", "languages": ["c"]}
            ]
            """);
        assertEquals(List.of("java", "python"), ledger.lookup("a").orElseThrow().languages());
        assertTrue(ledger.lookup("b").orElseThrow().exhibitedBy("c"));
        assertTrue(ledger.lookup("missing").isEmpty());
        assertEquals(List.of("a", "b"), List.copyOf(ledger.ids()));
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
            () -> KnownBugs.parse("[{\"description\": \"d\", \"languages\": [\"java\"]}]"));
        assertTrue(e.getMessage().contains("'id'"), e.getMessage());
    }

    @Test
    void blankDescriptionIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("[{\"id\": \"a\", \"description\": \" \", \"languages\": [\"java\"]}]"));
        assertTrue(e.getMessage().contains("'description'"), e.getMessage());
    }

    @Test
    void emptyLanguagesIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("[{\"id\": \"a\", \"description\": \"d\", \"languages\": []}]"));
        assertTrue(e.getMessage().contains("non-empty 'languages'"), e.getMessage());
    }

    @Test
    void duplicateBugIdIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse("""
                [
                  {"id": "a", "description": "d", "languages": ["java"]},
                  {"id": "a", "description": "d2", "languages": ["python"]}
                ]
                """));
        assertTrue(e.getMessage().contains("duplicate bug id"), e.getMessage());
    }

    @Test
    void duplicateLanguageIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"id\": \"a\", \"description\": \"d\", \"languages\": [\"java\", \"java\"]}]"));
        assertTrue(e.getMessage().contains("twice"), e.getMessage());
    }

    @Test
    void unknownEntryFieldIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> KnownBugs.parse(
                "[{\"id\": \"a\", \"description\": \"d\", \"languages\": [\"java\"], \"suites\": []}]"));
        assertTrue(e.getMessage().contains("unknown field 'suites'"), e.getMessage());
    }
}
