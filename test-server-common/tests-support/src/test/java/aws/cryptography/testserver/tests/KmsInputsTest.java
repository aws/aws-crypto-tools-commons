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
    void rejectsAnInputThatIsNotAKeyArn() {
        assertThrows(IllegalArgumentException.class, () -> KmsInputs.validKmsIdentifiers("alias/x"));
    }
}
