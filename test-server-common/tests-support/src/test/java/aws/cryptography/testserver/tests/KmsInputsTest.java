package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.tests.KmsInputs.Example;
import java.util.List;
import org.junit.jupiter.api.Test;

class KmsInputsTest {

    private static final String KEY_ARN = "arn:aws:kms:us-west-2:111122223333:key/1234abcd";

    @Test
    void validIdentifiersComeFromTheKeyArn() {
        assertEquals(
            List.of(KEY_ARN, "arn:aws:kms:us-west-2:111122223333:alias/x", "1234abcd", "alias/x"),
            KmsInputs.validKmsIdentifiers(KEY_ARN).stream().map(Example::value).toList());
    }

    @Test
    void invalidIdentifiersChangeOnePartOfTheKeyArn() {
        List<String> invalid = KmsInputs.invalidKmsIdentifiers(KEY_ARN).stream().map(Example::value).toList();
        assertTrue(invalid.contains("arn:aws:kms::111122223333:key/1234abcd"));
        assertTrue(invalid.contains("arn:aws:s3:us-west-2:111122223333:key/1234abcd"));
    }

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(14, KmsInputs.invalidKmsIdentifiers(KEY_ARN, KmsInputs.Fuzz.NONE).size());
    }

    @Test
    void fuzzAddsRandomExamplesThatTheSeedRepeats() {
        KmsInputs.Fuzz fuzz = new KmsInputs.Fuzz(50, 42);
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
    void rejectsAnInputThatIsNotAKeyArn() {
        assertThrows(IllegalArgumentException.class, () -> KmsInputs.validKmsIdentifiers("alias/x"));
    }
}
