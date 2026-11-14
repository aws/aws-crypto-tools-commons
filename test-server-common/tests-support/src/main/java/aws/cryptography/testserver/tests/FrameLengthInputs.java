package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.List;

/**
 * Frame lengths for a test that encrypts framed messages.
 *
 * <p>encrypt.md#frame-length says a frame length MUST be greater than 0 and MUST NOT exceed 2^32 - 1.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class FrameLengthInputs {

    private static final long MAX_FRAME_LENGTH = 0xFFFF_FFFFL;
    /** Random valid lengths stay small, so a message of a few frames stays small too. */
    private static final int MAX_RANDOM_VALID_LENGTH = 8192;
    /** Half of the random invalid lengths sit this close to a bound, where an off-by-one would show. */
    private static final int NEAR_BOUND = 8192;

    private FrameLengthInputs() {
    }

    /** Frame lengths that encrypt.md allows, each at most 8192 bytes. */
    public static List<Example<Long>> validFrameLengths() {
        return validFrameLengths(Fuzz.configured());
    }

    static List<Example<Long>> validFrameLengths(Fuzz fuzz) {
        List<Example<Long>> examples = new ArrayList<>(List.of(
            new Example<>("1 byte", 1L),
            new Example<>("16 bytes, the AES block size", 16L),
            new Example<>("999 bytes, not a multiple of the AES block size", 999L),
            new Example<>("4096 bytes", 4096L)));
        examples.addAll(fuzz.examples("validFrameLengths", random -> {
            long length = 1 + random.nextInt(MAX_RANDOM_VALID_LENGTH);
            return new Example<>(length + " bytes", length);
        }));
        return examples;
    }

    /** Frame lengths that are not greater than 0 or that exceed 2^32 - 1. */
    public static List<Example<Long>> invalidFrameLengths() {
        return invalidFrameLengths(Fuzz.configured());
    }

    static List<Example<Long>> invalidFrameLengths(Fuzz fuzz) {
        List<Example<Long>> examples = new ArrayList<>(List.of(
            new Example<>("-16", -16L),
            new Example<>("0", 0L)));
        examples.addAll(fuzz.examples("invalidFrameLengths", random -> {
            long length = switch (random.nextInt(4)) {
                case 0 -> -random.nextInt(NEAR_BOUND);
                case 1 -> -random.nextLong(Long.MAX_VALUE);
                case 2 -> MAX_FRAME_LENGTH + 1 + random.nextInt(NEAR_BOUND);
                default -> random.nextLong(MAX_FRAME_LENGTH + 1, Long.MAX_VALUE);
            };
            return new Example<>(String.valueOf(length), length);
        }));
        return examples;
    }
}
