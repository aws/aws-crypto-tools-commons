package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EncryptionContextInputsTest {

    private static final Fuzz FUZZ = new Fuzz(500, 42, null);

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(8, EncryptionContextInputs.validEncryptionContexts(Fuzz.NONE).size());
        assertEquals(List.of(Map.of("aws-crypto-public-key", "any-value")),
            EncryptionContextInputs.publicKeyEncryptionContexts(Fuzz.NONE).stream().map(Example::value).toList());
        assertEquals(List.of(Map.of("aws-crypto-not-a-real-reserved-key", "any-value")),
            EncryptionContextInputs.reservedPrefixEncryptionContexts(Fuzz.NONE).stream().map(Example::value).toList());
    }

    @Test
    void everyValidContextFollowsTheRules() {
        List<Map<String, String>> valid = EncryptionContextInputs.validEncryptionContexts(FUZZ).stream()
            .map(Example::value).toList();
        assertEquals(8 + 500, valid.size());
        for (Map<String, String> context : valid) {
            assertTrue(isWellFormedAndFits(context) && reservedKeys(context).isEmpty(), context.toString());
        }
        // The random contexts mix ASCII with characters of every longer UTF-8 width.
        List<Map<String, String>> random = valid.subList(8, valid.size());
        for (int width = 1; width <= 4; width++) {
            int utf8Width = width;
            assertTrue(random.stream().anyMatch(context -> context.keySet().stream()
                .anyMatch(key -> key.codePoints().anyMatch(c -> utf8Bytes(Character.toString(c)) == utf8Width))),
                "no random key has a character of " + width + " UTF-8 bytes");
        }
    }

    @Test
    void everyReservedContextBreaksOnlyTheReservedKeyRule() {
        for (Example<Map<String, String>> example : EncryptionContextInputs.publicKeyEncryptionContexts(FUZZ)) {
            Map<String, String> context = example.value();
            assertTrue(isWellFormedAndFits(context), example.name());
            assertEquals(List.of("aws-crypto-public-key"), reservedKeys(context), example.name());
        }
        for (Example<Map<String, String>> example : EncryptionContextInputs.reservedPrefixEncryptionContexts(FUZZ)) {
            Map<String, String> context = example.value();
            assertTrue(isWellFormedAndFits(context), example.name());
            List<String> reserved = reservedKeys(context);
            assertEquals(1, reserved.size(), example.name());
            assertTrue(!reserved.get(0).equals("aws-crypto-public-key"), example.name());
        }
    }

    @Test
    void withOneValueChangedChangesExactlyOneValue() {
        for (Example<Map<String, String>> example : EncryptionContextInputs.validEncryptionContexts(FUZZ)) {
            Map<String, String> context = example.value();
            if (context.isEmpty()) {
                continue;
            }
            Map<String, String> changed = EncryptionContextInputs.withOneValueChanged(context);
            assertEquals(context.keySet(), changed.keySet(), example.name());
            assertEquals(1, context.keySet().stream()
                .filter(key -> !context.get(key).equals(changed.get(key))).count(), example.name());
        }
        assertThrows(IllegalArgumentException.class, () -> EncryptionContextInputs.withOneValueChanged(Map.of()));
    }

    /**
     * Every key and value encodes as UTF-8, no key is empty,
     * and the serialized context fits the header's 2-byte length field, written out again here.
     */
    private static boolean isWellFormedAndFits(Map<String, String> context) {
        int serialized = 2;
        for (Map.Entry<String, String> entry : context.entrySet()) {
            if (entry.getKey().isEmpty() || !encodes(entry.getKey()) || !encodes(entry.getValue())) {
                return false;
            }
            serialized += 2 + utf8Bytes(entry.getKey()) + 2 + utf8Bytes(entry.getValue());
        }
        return serialized <= 0xFFFF;
    }

    private static List<String> reservedKeys(Map<String, String> context) {
        return context.keySet().stream().filter(key -> key.startsWith("aws-crypto-")).toList();
    }

    private static boolean encodes(String text) {
        return StandardCharsets.UTF_8.newEncoder().canEncode(text);
    }

    private static int utf8Bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }
}
