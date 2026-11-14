package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class FrameLengthInputsTest {

    private static final Fuzz FUZZ = new Fuzz(500, 42, null);

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(List.of(1L, 16L, 999L, 4096L),
            FrameLengthInputs.validFrameLengths(Fuzz.NONE).stream().map(Example::value).toList());
        assertEquals(List.of(-16L, 0L),
            FrameLengthInputs.invalidFrameLengths(Fuzz.NONE).stream().map(Example::value).toList());
    }

    @Test
    void everyFrameLengthFollowsTheRuleItsListClaims() {
        for (Example<Long> valid : FrameLengthInputs.validFrameLengths(FUZZ)) {
            assertTrue(isValidFrameLength(valid.value()) && valid.value() <= 8192, valid.name());
        }
        List<Example<Long>> invalid = FrameLengthInputs.invalidFrameLengths(FUZZ);
        for (Example<Long> example : invalid) {
            assertTrue(!isValidFrameLength(example.value()), example.name());
        }
        assertTrue(invalid.stream().anyMatch(e -> e.value() <= 0), "no frame length below the range");
        assertTrue(invalid.stream().anyMatch(e -> e.value() > 0), "no frame length above the range");
    }

    /** encrypt.md#frame-length, written out again here: greater than 0 and at most 2^32 - 1. */
    private static boolean isValidFrameLength(long frameLength) {
        return frameLength > 0 && frameLength <= 4_294_967_295L;
    }
}
