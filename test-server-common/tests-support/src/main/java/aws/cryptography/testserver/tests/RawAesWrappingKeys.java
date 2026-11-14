package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

/**
 * Wrapping keys for a raw AES keyring, each paired with the wrapping algorithm to build the keyring with.
 *
 * <p>raw-aes-keyring.md in the specification allows AES-GCM with a 128, 192 or 256-bit key,
 * and says the keyring must fail to build when the key's length does not match the algorithm's.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class RawAesWrappingKeys {

    private static final int[] ALGORITHM_KEY_LENGTHS = {16, 24, 32};
    private static final int MAX_INVALID_KEY_LENGTH = 128;

    private RawAesWrappingKeys() {
    }

    /**
     * A wrapping key and the wrapping algorithm to build the keyring with.
     *
     * @param algorithmKeyLength the key length in bytes that the algorithm uses: 16 for AES-128,
     *     24 for AES-192 or 32 for AES-256
     * @param key the wrapping key
     */
    public record WrappingKey(int algorithmKeyLength, byte[] key) {
        @Override
        public String toString() {
            return "AES-" + algorithmKeyLength * 8 + " with a " + key.length + "-byte key "
                + HexFormat.of().formatHex(key);
        }
    }

    /** One key of the right length for each wrapping algorithm. */
    public static List<Example<WrappingKey>> validWrappingKeys() {
        return validWrappingKeys(Fuzz.configured());
    }

    static List<Example<WrappingKey>> validWrappingKeys(Fuzz fuzz) {
        List<Example<WrappingKey>> examples = new ArrayList<>();
        for (int length : ALGORITHM_KEY_LENGTHS) {
            examples.add(example(length, countingBytes(length)));
        }
        examples.addAll(fuzz.examples("validWrappingKeys", random -> {
            int length = ALGORITHM_KEY_LENGTHS[random.nextInt(ALGORITHM_KEY_LENGTHS.length)];
            byte[] key = new byte[length];
            random.nextBytes(key);
            return example(length, key);
        }));
        return examples;
    }

    /**
     * Keys whose length does not match their wrapping algorithm.
     * Some have a length that no algorithm uses; others fit a different algorithm.
     */
    public static List<Example<WrappingKey>> invalidWrappingKeys() {
        return invalidWrappingKeys(Fuzz.configured());
    }

    static List<Example<WrappingKey>> invalidWrappingKeys(Fuzz fuzz) {
        List<Example<WrappingKey>> examples = new ArrayList<>();
        for (int length : new int[] {0, 15, 16, 17, 24, 31, 33, 64}) {
            examples.add(example(32, countingBytes(length)));
        }
        examples.add(example(16, countingBytes(32)));
        examples.add(example(24, countingBytes(32)));
        examples.addAll(fuzz.examples("invalidWrappingKeys", random -> {
            int algorithmKeyLength = ALGORITHM_KEY_LENGTHS[random.nextInt(ALGORITHM_KEY_LENGTHS.length)];
            // Any length from 0 to 128 except the algorithm's own.
            int length = random.nextInt(MAX_INVALID_KEY_LENGTH);
            if (length >= algorithmKeyLength) {
                length++;
            }
            byte[] key = new byte[length];
            random.nextBytes(key);
            return example(algorithmKeyLength, key);
        }));
        return examples;
    }

    private static Example<WrappingKey> example(int algorithmKeyLength, byte[] key) {
        return new Example<>(key.length + "-byte key for AES-" + algorithmKeyLength * 8,
            new WrappingKey(algorithmKeyLength, key));
    }

    /** The bytes 0, 1, 2 and so on: a fixed key that is easy to spot in a log. */
    private static byte[] countingBytes(int length) {
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            key[i] = (byte) i;
        }
        return key;
    }
}
