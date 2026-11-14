package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FuzzTest {

    private static List<Example<Integer>> numbers(Fuzz fuzz, String list) {
        return fuzz.examples(list, random -> new Example<>("number", random.nextInt()));
    }

    @Test
    void noFuzzAddsNothing() {
        assertEquals(List.of(), numbers(Fuzz.NONE, "numbers"));
    }

    @Test
    void theSeedMakesTheSameExamplesAgain() {
        List<Example<Integer>> first = numbers(new Fuzz(20, 42, null), "numbers");
        assertEquals(20, first.size());
        assertEquals(first, numbers(new Fuzz(20, 42, null), "numbers"));
        assertNotEquals(first, numbers(new Fuzz(20, 43, null), "numbers"));
    }

    @Test
    void eachListGetsItsOwnRandomValues() {
        assertNotEquals(numbers(new Fuzz(20, 42, null), "numbers").stream().map(Example::value).toList(),
            numbers(new Fuzz(20, 42, null), "otherNumbers").stream().map(Example::value).toList());
    }

    @Test
    void eachNameHasItsNumberAndSeed() {
        assertEquals("fuzz 1 seed=-7: number", numbers(new Fuzz(2, -7, null), "numbers").get(1).name());
    }

    @Test
    void eachRandomExampleIsWrittenToTheLog(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("fuzz-log.jsonl");
        List<Example<String>> examples = new Fuzz(3, 7, log)
            .examples("longStrings", random -> new Example<>("long string", "a".repeat(500)));
        List<String> lines = Files.readAllLines(log);
        assertEquals(3, lines.size());
        JsonNode first = new ObjectMapper().readTree(lines.get(0));
        assertEquals("FuzzTest", first.get("family").asText());
        assertEquals("longStrings", first.get("list").asText());
        assertEquals(FuzzTest.class.getName(), first.get("test").asText());
        assertEquals(7, first.get("seed").asLong());
        assertEquals(0, first.get("index").asInt());
        assertEquals("long string", first.get("what").asText());
        assertEquals(examples.get(0).name(), first.get("name").asText());
        assertEquals(500, first.get("length").asInt());
        assertTrue(first.get("value").asText().length() <= 203, "long values keep only their start and end");
    }

    @Test
    void aLongValueIsNotCutInsideAnEmoji(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("fuzz-log.jsonl");
        // Character 100 is the second half of an emoji, at both the start and the end.
        String value = "a".repeat(99) + "\ud83d\ude80" + "b".repeat(300) + "\ud83d\ude80" + "c".repeat(99);
        new Fuzz(1, 7, log).examples("emoji", random -> new Example<>("emoji at the cut", value));
        String logged = new ObjectMapper().readTree(Files.readAllLines(log).get(0)).get("value").asText();
        assertEquals("a".repeat(99) + "\ud83d\ude80...\ud83d\ude80" + "c".repeat(99), logged);
    }

    @Test
    void bytesAreLoggedAsHex(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("fuzz-log.jsonl");
        new Fuzz(1, 7, log).examples("bytes", random -> new Example<>("two bytes", new byte[] {1, (byte) 0xff}));
        JsonNode line = new ObjectMapper().readTree(Files.readAllLines(log).get(0));
        assertEquals("01ff", line.get("value").asText());
        assertEquals(2, line.get("length").asInt());
    }
}
