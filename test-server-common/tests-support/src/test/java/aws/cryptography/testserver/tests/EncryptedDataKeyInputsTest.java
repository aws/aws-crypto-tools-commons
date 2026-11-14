package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.tests.EncryptedDataKeyInputs.EdkMaximums;
import java.util.List;
import org.junit.jupiter.api.Test;

class EncryptedDataKeyInputsTest {

    @Test
    void defaultRunHasOnlyTheFixedExample() {
        assertEquals(List.of(new EdkMaximums(2, 2, 1)),
            EncryptedDataKeyInputs.edkMaximums(Fuzz.NONE).stream().map(Example::value).toList());
    }

    @Test
    void eachMaximumAllowsOrRejectsAsItsNameSays() {
        for (Example<EdkMaximums> example : EncryptedDataKeyInputs.edkMaximums(new Fuzz(500, 42, null))) {
            EdkMaximums maximums = example.value();
            assertTrue(maximums.edkCount() <= maximums.maximumThatAllows(), example.name());
            assertTrue(1 <= maximums.maximumThatRejects() && maximums.maximumThatRejects() < maximums.edkCount(),
                example.name());
        }
    }
}
