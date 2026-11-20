package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class KmsInputsTest {

    private static final String KEY_ARN = "arn:aws:kms:us-west-2:111122223333:key/1234abcd";

    @Test
    void validIdentifiersComeFromTheKeyArn() {
        assertEquals(
            List.of(KEY_ARN, "arn:aws:kms:us-west-2:111122223333:alias/x", "1234abcd", "alias/x"),
            KmsInputs.validKmsIdentifiers(KEY_ARN, Fuzz.NONE).stream().map(Example::value).toList());
    }

    @Test
    void invalidIdentifiersChangeOnePartOfTheKeyArn() {
        List<String> invalid = KmsInputs.invalidKmsIdentifiers(KEY_ARN, Fuzz.NONE).stream().map(Example::value).toList();
        assertTrue(invalid.contains("arn:aws:kms::111122223333:key/1234abcd"));
        assertTrue(invalid.contains("arn:aws:s3:us-west-2:111122223333:key/1234abcd"));
    }

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(14, KmsInputs.invalidKmsIdentifiers(KEY_ARN, Fuzz.NONE).size());
    }

    @Test
    void fuzzAddsRandomExamplesThatTheSeedRepeats() {
        Fuzz fuzz = new Fuzz(50, 42, null);
        List<Example<String>> first = KmsInputs.invalidKmsIdentifiers(KEY_ARN, fuzz);
        assertEquals(14 + 50, first.size());
        assertEquals(first, KmsInputs.invalidKmsIdentifiers(KEY_ARN, fuzz));
        assertTrue(first.get(14).name().startsWith("fuzz 0 seed=42: "));
        assertEquals(2 + 50, KmsInputs.validGrantTokenLists(fuzz).size());
        assertTrue(KmsInputs.validGrantTokenLists(fuzz).stream()
            .allMatch(e -> e.value().size() <= 10 && e.value().stream().allMatch(t -> !t.isEmpty() && t.length() <= 8192)));
        assertTrue(KmsInputs.invalidGrantTokenLists(fuzz).stream()
            .allMatch(e -> e.value().size() > 10 || e.value().stream().anyMatch(t -> t.isEmpty() || t.length() > 8192)));
    }

    @Test
    void everyIdentifierFollowsTheRuleItsListClaims() {
        Fuzz fuzz = new Fuzz(500, 42, null);
        for (Example<String> valid : KmsInputs.validKmsIdentifiers(KEY_ARN, fuzz)) {
            assertTrue(isValidKmsIdentifier(valid.value()), valid.name() + ": " + valid.value());
        }
        for (Example<String> invalid : KmsInputs.invalidKmsIdentifiers(KEY_ARN, fuzz)) {
            assertTrue(!isValidKmsIdentifier(invalid.value()), invalid.name() + ": " + invalid.value());
        }
    }

    /** The rules in aws-kms-key-arn.md, written out again here so the lists are checked against them. */
    private static boolean isValidKmsIdentifier(String identifier) {
        if (identifier.isEmpty() || identifier.length() > 2048
                || !identifier.chars().allMatch(c -> c < 0x80)) {
            return false;
        }
        if (identifier.startsWith("arn:")) {
            String[] parts = identifier.split(":", -1);
            if (parts.length != 6 || !parts[2].equals("kms")
                    || parts[1].isEmpty() || parts[3].isEmpty() || parts[4].isEmpty()) {
                return false;
            }
            String[] resource = parts[5].split("/", 2);
            return resource.length == 2 && !resource[1].isEmpty()
                && (resource[0].equals("key") || resource[0].equals("alias"));
        }
        if (identifier.startsWith("alias/")) {
            return identifier.length() > "alias/".length();
        }
        return !identifier.contains("/");
    }

    @Test
    void rejectsAnInputThatIsNotAKeyArn() {
        assertThrows(IllegalArgumentException.class, () -> KmsInputs.validKmsIdentifiers("alias/x"));
    }
}
