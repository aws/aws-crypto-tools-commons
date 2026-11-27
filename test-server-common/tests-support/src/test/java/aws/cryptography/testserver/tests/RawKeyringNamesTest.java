package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.tests.RawKeyringNames.KeyNames;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class RawKeyringNamesTest {

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(6, RawKeyringNames.validKeyNames(Fuzz.NONE).size());
        assertEquals(List.of(new KeyNames("aws-kms", "test-server-key")),
            RawKeyringNames.invalidKeyNames().stream().map(Example::value).toList());
    }

    @Test
    void fuzzAddsRandomExamplesThatTheSeedRepeats() {
        Fuzz fuzz = new Fuzz(50, 42, null);
        List<Example<KeyNames>> first = RawKeyringNames.validKeyNames(fuzz);
        assertEquals(6 + 50, first.size());
        assertEquals(first, RawKeyringNames.validKeyNames(fuzz));
        assertTrue(first.get(6).name().startsWith("fuzz 0 seed=42: random names of "));
    }

    @Test
    void randomNamesHaveNonAsciiAndSupplementaryCodePoints() {
        List<String> names = RawKeyringNames.validKeyNames(new Fuzz(50, 42, null)).stream()
            .skip(6).map(e -> e.value().keyName()).toList();
        assertTrue(names.stream().anyMatch(n -> n.chars().anyMatch(c -> c >= 0x80 && c < 0xd800)));
        assertTrue(names.stream().anyMatch(n -> n.codePoints().anyMatch(c -> c >= 0x10000)));
    }

    @Test
    void everyExampleFollowsTheRuleItsListClaims() {
        for (Example<KeyNames> valid : RawKeyringNames.validKeyNames(new Fuzz(500, 42, null))) {
            assertTrue(isValid(valid.value()), valid.name() + ": " + valid.value());
        }
        for (Example<KeyNames> invalid : RawKeyringNames.invalidKeyNames()) {
            assertFalse(isValid(invalid.value()), invalid.name() + ": " + invalid.value());
        }
    }

    /**
     * The rules for a raw keyring's names, written out again here so the lists are checked against them.
     * Each name must be a string that UTF-8 can encode, so no unpaired surrogates.
     * The key namespace must not be aws-kms, and the key provider ID that it becomes must not start with aws-kms.
     * Each encrypted data key field has a 2-byte length.
     * The raw AES key provider info holds the key name and 20 more bytes, so the key name gets 20 fewer.
     */
    private static boolean isValid(KeyNames names) {
        String namespace = names.keyNamespace();
        String keyName = names.keyName();
        return encodesToUtf8(namespace) && encodesToUtf8(keyName)
            && !namespace.startsWith("aws-kms")
            && namespace.getBytes(StandardCharsets.UTF_8).length <= 0xffff
            && keyName.getBytes(StandardCharsets.UTF_8).length <= 0xffff - 20;
    }

    // Java writes '?' for an unpaired surrogate, so such a string does not come back unchanged.
    private static boolean encodesToUtf8(String text) {
        return new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8).equals(text);
    }
}
