package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.tests.RawAesWrappingKeys.WrappingKey;
import java.util.List;
import org.junit.jupiter.api.Test;

class RawAesWrappingKeysTest {

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(List.of("16-byte key for AES-128", "24-byte key for AES-192", "32-byte key for AES-256"),
            RawAesWrappingKeys.validWrappingKeys(Fuzz.NONE).stream().map(Example::name).toList());
        assertEquals(10, RawAesWrappingKeys.invalidWrappingKeys(Fuzz.NONE).size());
    }

    @Test
    void fuzzAddsRandomExamplesThatTheSeedRepeats() {
        Fuzz fuzz = new Fuzz(50, 42, null);
        List<Example<WrappingKey>> first = RawAesWrappingKeys.invalidWrappingKeys(fuzz);
        assertEquals(10 + 50, first.size());
        // A record compares a byte[] by reference, so compare what toString prints, which has the key bytes.
        assertEquals(first.stream().map(e -> e.value().toString()).toList(),
            RawAesWrappingKeys.invalidWrappingKeys(fuzz).stream().map(e -> e.value().toString()).toList());
        assertTrue(first.get(10).name().startsWith("fuzz 0 seed=42: "));
    }

    @Test
    void everyKeyFollowsTheRuleItsListClaims() {
        Fuzz fuzz = new Fuzz(500, 42, null);
        for (Example<WrappingKey> valid : RawAesWrappingKeys.validWrappingKeys(fuzz)) {
            assertTrue(isValid(valid.value()), valid.name());
        }
        for (Example<WrappingKey> invalid : RawAesWrappingKeys.invalidWrappingKeys(fuzz)) {
            assertFalse(isValid(invalid.value()), invalid.name());
            assertTrue(invalid.value().key().length <= 128, invalid.name());
        }
    }

    /** The rule in raw-aes-keyring.md, written out again here so the lists are checked against it. */
    private static boolean isValid(WrappingKey wrappingKey) {
        int algorithmKeyLength = wrappingKey.algorithmKeyLength();
        return (algorithmKeyLength == 16 || algorithmKeyLength == 24 || algorithmKeyLength == 32)
            && wrappingKey.key().length == algorithmKeyLength;
    }
}
