package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Encryption contexts that any test that encrypts or gets materials from a CMM can reuse.
 *
 * <p>The rules come from structures.md#encryption-context and encrypt.md#encryption-context
 * in the specification: keys and values are UTF-8 strings,
 * the serialized context must fit the header's 2-byte length field,
 * and encrypt fails for a caller key that begins with {@code aws-crypto-}.
 *
 * <p>Each map keeps its insertion order, so a test that changes "the first value" changes the same one every run.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class EncryptionContextInputs {

    private static final String RESERVED_PREFIX = "aws-crypto-";
    /** The reserved key that the Default CMM writes for a signing algorithm suite. */
    private static final String PUBLIC_KEY_KEY = "aws-crypto-public-key";
    private static final int MAX_RANDOM_PAIRS = 8;
    private static final int MAX_RANDOM_KEY_LENGTH = 16;
    private static final int MAX_RANDOM_VALUE_LENGTH = 32;

    private EncryptionContextInputs() {
    }

    /** Encryption contexts that encrypt must accept and decrypt must give back unchanged. */
    public static List<Example<Map<String, String>>> validEncryptionContexts() {
        return validEncryptionContexts(Fuzz.configured());
    }

    static List<Example<Map<String, String>>> validEncryptionContexts(Fuzz fuzz) {
        Map<String, String> manyPairs = new LinkedHashMap<>();
        for (int i = 0; i < 100; i++) {
            manyPairs.put(String.format("key-%03d", i), "value-" + i);
        }
        List<Example<Map<String, String>>> examples = new ArrayList<>(List.of(
            new Example<>("empty", pairs()),
            new Example<>("one pair", pairs("purpose", "test")),
            new Example<>("two pairs", pairs("purpose", "test", "tenant", "acme")),
            // The header must list keys in sorted order, whatever order the caller gives.
            new Example<>("keys out of order", pairs("zebra", "1", "alpha", "2", "mango", "3")),
            new Example<>("CJK key, emoji key and emoji value",
                pairs("\u65e5\u672c\u8a9e", "value", "key-\ud83d\udd11", "\ud83d\ude80")),
            // Only a key that begins with "aws-crypto-", hyphen included, is reserved.
            new Example<>("key aws-crypto without the hyphen",
                pairs("aws-crypto", "no-trailing-hyphen-is-not-reserved")),
            new Example<>("100 pairs", Collections.unmodifiableMap(manyPairs)),
            new Example<>("a value of 8192 characters", pairs("k", "a".repeat(8192)))));
        examples.addAll(fuzz.examples("validEncryptionContexts", random -> {
            Map<String, String> context = randomPairs(random, 1 + random.nextInt(MAX_RANDOM_PAIRS));
            return new Example<>(context.size() + " random pairs", Collections.unmodifiableMap(context));
        }));
        return examples;
    }

    /**
     * Encryption contexts holding the {@code aws-crypto-public-key} key, which encrypt must reject.
     * The other pairs are valid, so that key is the only reason to reject.
     */
    public static List<Example<Map<String, String>>> publicKeyEncryptionContexts() {
        return publicKeyEncryptionContexts(Fuzz.configured());
    }

    static List<Example<Map<String, String>>> publicKeyEncryptionContexts(Fuzz fuzz) {
        List<Example<Map<String, String>>> examples = new ArrayList<>(List.of(
            new Example<>(PUBLIC_KEY_KEY, pairs(PUBLIC_KEY_KEY, "any-value"))));
        examples.addAll(fuzz.examples("publicKeyEncryptionContexts", random -> {
            Map<String, String> context = withPair(random, randomPairs(random, random.nextInt(4)),
                PUBLIC_KEY_KEY, randomText(random, 1 + random.nextInt(MAX_RANDOM_VALUE_LENGTH)));
            return new Example<>(PUBLIC_KEY_KEY + " among " + context.size() + " pairs", context);
        }));
        return examples;
    }

    /**
     * Encryption contexts holding a key that begins with {@code aws-crypto-} and is not
     * {@code aws-crypto-public-key}, which encrypt must also reject.
     * The other pairs are valid, so that key is the only reason to reject.
     */
    public static List<Example<Map<String, String>>> reservedPrefixEncryptionContexts() {
        return reservedPrefixEncryptionContexts(Fuzz.configured());
    }

    static List<Example<Map<String, String>>> reservedPrefixEncryptionContexts(Fuzz fuzz) {
        List<Example<Map<String, String>>> examples = new ArrayList<>(List.of(
            new Example<>("aws-crypto-not-a-real-reserved-key",
                pairs("aws-crypto-not-a-real-reserved-key", "any-value"))));
        examples.addAll(fuzz.examples("reservedPrefixEncryptionContexts", random -> {
            String suffix = randomText(random, 1 + random.nextInt(MAX_RANDOM_KEY_LENGTH));
            // Servers with the known bug encrypt-accepts-reserved-prefix-encryption-context-key
            // still reject aws-crypto-public-key, so that key belongs only in publicKeyEncryptionContexts.
            String key = RESERVED_PREFIX + (suffix.equals("public-key") ? "x" + suffix : suffix);
            Map<String, String> context = withPair(random, randomPairs(random, random.nextInt(4)),
                key, randomText(random, 1 + random.nextInt(MAX_RANDOM_VALUE_LENGTH)));
            return new Example<>("random aws-crypto- key among " + context.size() + " pairs", context);
        }));
        return examples;
    }

    /**
     * {@code context} with its first value changed, for a test that decrypt rejects a context
     * that differs from the one the message was encrypted with.
     */
    public static Map<String, String> withOneValueChanged(Map<String, String> context) {
        if (context.isEmpty()) {
            throw new IllegalArgumentException("an empty encryption context has no value to change");
        }
        Map<String, String> changed = new LinkedHashMap<>(context);
        String key = changed.keySet().iterator().next();
        changed.put(key, changed.get(key) + "x");
        return Collections.unmodifiableMap(changed);
    }

    /** A map of the given keys and values, in that order. */
    private static Map<String, String> pairs(String... keysAndValues) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Up to {@code count} random pairs; two equal random keys make one pair.
     * Values are never empty: the message format allows an empty value,
     * but some servers reject it as the known bug encrypt-rejects-empty-encryption-context-value.
     */
    private static Map<String, String> randomPairs(Random random, int count) {
        Map<String, String> context = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            String key = randomText(random, 1 + random.nextInt(MAX_RANDOM_KEY_LENGTH));
            if (key.startsWith(RESERVED_PREFIX)) {
                key = "k" + key;
            }
            context.put(key, randomText(random, 1 + random.nextInt(MAX_RANDOM_VALUE_LENGTH)));
        }
        return context;
    }

    /** {@code context} with one more pair at a random position. */
    private static Map<String, String> withPair(Random random, Map<String, String> context,
            String key, String value) {
        List<Map.Entry<String, String>> entries = new ArrayList<>(context.entrySet());
        entries.add(random.nextInt(entries.size() + 1), Map.entry(key, value));
        Map<String, String> result = new LinkedHashMap<>();
        entries.forEach(entry -> result.put(entry.getKey(), entry.getValue()));
        return Collections.unmodifiableMap(result);
    }

    /**
     * {@code length} random code points: half printable ASCII,
     * the rest spread over the 2-, 3- and 4-byte UTF-8 widths.
     * Surrogate code points are never picked, so the text is always valid UTF-8.
     */
    private static String randomText(Random random, int length) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int codePoint;
            if (random.nextBoolean()) {
                codePoint = 0x20 + random.nextInt(0x7F - 0x20);
            } else {
                codePoint = switch (random.nextInt(3)) {
                    case 0 -> 0x80 + random.nextInt(0x800 - 0x80);
                    case 1 -> {
                        // 0xD800 to 0xDFFF are surrogates, which UTF-8 cannot encode on their own.
                        int threeByte = 0x800 + random.nextInt(0x10000 - 0x800 - 0x800);
                        yield threeByte < 0xD800 ? threeByte : threeByte + 0x800;
                    }
                    default -> 0x10000 + random.nextInt(0x110000 - 0x10000);
                };
            }
            text.appendCodePoint(codePoint);
        }
        return text.toString();
    }
}
