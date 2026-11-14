package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Key namespaces and key names for a raw AES or raw RSA keyring.
 *
 * <p>A raw keyring writes its key namespace as the encrypted data key's key provider ID,
 * and its key name into the key provider info, both as UTF-8.
 * A decrypting keyring in another language must read back exactly those bytes to find its key.
 * The rules come from keyring-interface.md, raw-aes-keyring.md and raw-rsa-keyring.md in the specification.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class RawKeyringNames {

    /** The key namespace that raw-aes-keyring.md and raw-rsa-keyring.md say the keyring must not accept. */
    private static final String RESERVED_NAMESPACE = "aws-kms";

    private static final String NAMESPACE = "test-server-namespace";
    private static final String KEY_NAME = "test-server-key";
    private static final int MAX_RANDOM_CODE_POINTS = 256;

    private RawKeyringNames() {
    }

    /** A key namespace and key name to build one raw keyring with. */
    public record KeyNames(String keyNamespace, String keyName) {
    }

    /** Key namespaces and key names that a raw keyring must accept and that must round-trip across languages. */
    public static List<Example<KeyNames>> validKeyNames() {
        return validKeyNames(Fuzz.configured());
    }

    static List<Example<KeyNames>> validKeyNames(Fuzz fuzz) {
        List<Example<KeyNames>> examples = new ArrayList<>(List.of(
            new Example<>("ASCII", new KeyNames(NAMESPACE, KEY_NAME)),
            // Each of these characters takes 2 or 3 bytes in UTF-8.
            new Example<>("non-ASCII", new KeyNames("\u6a19\u6e96-namespace", "raw-aes-\u043a\u043b\u044e\u0447")),
            // Each emoji takes 4 bytes in UTF-8 and 2 chars in Java, JavaScript and .NET strings.
            new Example<>("emoji", new KeyNames("namespace-\ud83d\udd11", "key-\ud83d\udd12")),
            new Example<>("'/' and ':'", new KeyNames("arn:aws:example:us-west-2:111122223333", "path/to/key:v1")),
            new Example<>("1000 characters", new KeyNames("n".repeat(1000), "k".repeat(1000))),
            // Only the key namespace is reserved.
            new Example<>("key name aws-kms", new KeyNames(NAMESPACE, RESERVED_NAMESPACE))));
        examples.addAll(fuzz.examples("validKeyNames", random -> {
            String namespace = randomText(random);
            // keyring-interface.md reserves key provider IDs that start with aws-kms for the AWS KMS keyrings.
            if (namespace.startsWith(RESERVED_NAMESPACE)) {
                namespace = "x" + namespace;
            }
            String keyName = randomText(random);
            return new Example<>("random names of " + namespace.codePointCount(0, namespace.length())
                + " and " + keyName.codePointCount(0, keyName.length()) + " code points",
                new KeyNames(namespace, keyName));
        }));
        return examples;
    }

    /**
     * Key namespaces and key names that a raw keyring must reject when it is built.
     * There are no random ones: the only rule is the one reserved key namespace.
     */
    public static List<Example<KeyNames>> invalidKeyNames() {
        return List.of(new Example<>("key namespace aws-kms", new KeyNames(RESERVED_NAMESPACE, KEY_NAME)));
    }

    /**
     * 1 to 256 code points, each printable ASCII, other Basic Multilingual Plane, or above it.
     * 256 code points take at most 1024 bytes in UTF-8, well inside the 2-byte length that each
     * encrypted data key field has.
     * Surrogates are left out because only a pair of them makes a code point.
     */
    private static String randomText(Random random) {
        int length = 1 + random.nextInt(MAX_RANDOM_CODE_POINTS);
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int codePoint = switch (random.nextInt(3)) {
                case 0 -> 0x20 + random.nextInt(0x7f - 0x20);
                case 1 -> {
                    int bmp = 0x80 + random.nextInt(0x10000 - 0x80 - 0x800);
                    yield bmp >= 0xd800 ? bmp + 0x800 : bmp;
                }
                default -> 0x10000 + random.nextInt(0x110000 - 0x10000);
            };
            text.appendCodePoint(codePoint);
        }
        return text.toString();
    }
}
