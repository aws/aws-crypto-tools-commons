package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.List;

/**
 * Encrypted data key counts for a test of the client's maximum number of encrypted data keys.
 *
 * <p>encrypt.md and decrypt.md say encrypt and decrypt fail when a message has more encrypted data keys
 * than the client's maximum.
 * The maximums here are at least 1, because creating a client with a maximum of 0 is a different rule.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class EncryptedDataKeyInputs {

    private static final int MAX_RANDOM_EDK_COUNT = 10;
    private static final int MAX_RANDOM_HEADROOM = 20;

    private EncryptedDataKeyInputs() {
    }

    /**
     * A message with {@code edkCount} encrypted data keys, a maximum that allows it,
     * and a maximum that rejects it.
     *
     * @param maximumThatAllows at least {@code edkCount}
     * @param maximumThatRejects at least 1 and less than {@code edkCount}
     */
    public record EdkMaximums(int edkCount, long maximumThatAllows, long maximumThatRejects) {
    }

    /** Encrypted data key counts of 2 to 10, each with a maximum that allows it and one that rejects it. */
    public static List<Example<EdkMaximums>> edkMaximums() {
        return edkMaximums(Fuzz.configured());
    }

    static List<Example<EdkMaximums>> edkMaximums(Fuzz fuzz) {
        List<Example<EdkMaximums>> examples = new ArrayList<>(List.of(
            new Example<>("2 EDKs, maximums 2 and 1", new EdkMaximums(2, 2, 1))));
        examples.addAll(fuzz.examples("edkMaximums", random -> {
            // A count of 1 has no maximum that rejects it.
            int edkCount = 2 + random.nextInt(MAX_RANDOM_EDK_COUNT - 1);
            long allows = edkCount + random.nextInt(MAX_RANDOM_HEADROOM + 1);
            long rejects = 1 + random.nextInt(edkCount - 1);
            return new Example<>(edkCount + " EDKs, maximums " + allows + " and " + rejects,
                new EdkMaximums(edkCount, allows, rejects));
        }));
        return examples;
    }
}
