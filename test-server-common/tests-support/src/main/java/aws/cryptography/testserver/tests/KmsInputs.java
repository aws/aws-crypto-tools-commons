package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.stream.IntStream;

/**
 * Valid and invalid KMS inputs that any test that configures AWS KMS can reuse,
 * such as the AWS KMS keyring tests or an ESDK test that builds a KMS keyring.
 *
 * <p>Each list is a fixed set of examples, each with a name for the test report.
 * The rules come from the KMS documentation and from aws-kms-key-arn.md in the specification.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class KmsInputs {

    private static final String ALIAS = "alias/x";
    private static final int MAX_IDENTIFIER_LENGTH = 2048;
    private static final int MAX_GRANT_TOKENS = 10;
    private static final int MAX_GRANT_TOKEN_LENGTH = 8192;

    private KmsInputs() {
    }

    /**
     * Every form of KMS identifier that aws-kms-key-arn.md calls valid:
     * {@code keyArn} itself, its key ID, an alias ARN in the same account and Region, and a raw alias.
     *
     * @param keyArn a key ARN, such as {@code arn:aws:kms:us-west-2:111122223333:key/<key ID>}
     */
    public static List<Example<String>> validKmsIdentifiers(String keyArn) {
        return validKmsIdentifiers(keyArn, Fuzz.configured());
    }

    static List<Example<String>> validKmsIdentifiers(String keyArn, Fuzz fuzz) {
        KeyArn arn = KeyArn.parse(keyArn);
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("key ARN", keyArn),
            new Example<>("alias ARN", arn.prefix() + ALIAS),
            new Example<>("raw key ID", arn.keyId()),
            new Example<>("raw alias", ALIAS)));
        examples.addAll(fuzz.examples("validKmsIdentifiers", random -> switch (random.nextInt(4)) {
            case 0 -> new Example<>("key ARN with a random key ID", arn.prefix() + "key/" + uuid(random));
            case 1 -> new Example<>("alias ARN with a random name", arn.prefix() + "alias/" + aliasName(random));
            case 2 -> new Example<>("random raw key ID", uuid(random));
            default -> new Example<>("random raw alias", "alias/" + aliasName(random));
        }));
        return examples;
    }

    /**
     * KMS identifiers that aws-kms-key-arn.md does not call valid.
     * Each one is {@code keyArn} with one thing wrong, or a raw form that is close to valid.
     *
     * @param keyArn a key ARN, such as {@code arn:aws:kms:us-west-2:111122223333:key/<key ID>}
     */
    public static List<Example<String>> invalidKmsIdentifiers(String keyArn) {
        return invalidKmsIdentifiers(keyArn, Fuzz.configured());
    }

    static List<Example<String>> invalidKmsIdentifiers(String keyArn, Fuzz fuzz) {
        KeyArn arn = KeyArn.parse(keyArn);
        String keyId = arn.keyId();
        String region = arn.region();
        String account = arn.account();
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("non-ASCII character", keyArn.substring(0, keyArn.length() - 1) + "\u00e9"),
            // A raw alias that is valid apart from its length.
            new Example<>("2049 characters", "alias/" + "a".repeat(MAX_IDENTIFIER_LENGTH + 1 - "alias/".length())),
            new Example<>("5-part ARN", "arn:aws:kms:" + region + ":" + account),
            new Example<>("7-part ARN", keyArn + ":extra"),
            new Example<>("empty partition", "arn::kms:" + region + ":" + account + ":key/" + keyId),
            new Example<>("empty Region", "arn:aws:kms::" + account + ":key/" + keyId),
            new Example<>("empty account", "arn:aws:kms:" + region + "::key/" + keyId),
            new Example<>("service s3", "arn:aws:s3:" + region + ":" + account + ":key/" + keyId),
            new Example<>("ARN resource foo/x", arn.prefix() + "foo/x"),
            new Example<>("ARN resource key/", arn.prefix() + "key/"),
            new Example<>("ARN resource key", arn.prefix() + "key"),
            new Example<>("raw key/<key ID>", "key/" + keyId),
            new Example<>("raw foo/bar", "foo/bar"),
            new Example<>("raw alias/", "alias/")));
        // Each change below breaks a rule on its own, whatever the random parts are.
        examples.addAll(fuzz.examples("invalidKmsIdentifiers", random -> switch (random.nextInt(6)) {
            case 0 -> {
                int at = random.nextInt(keyArn.length() + 1);
                yield new Example<>("non-ASCII character at " + at,
                    keyArn.substring(0, at) + (char) (0x80 + random.nextInt(0x700)) + keyArn.substring(at));
            }
            case 1 -> {
                int length = MAX_IDENTIFIER_LENGTH + 1 + random.nextInt(2048);
                yield new Example<>(length + " characters", "alias/" + "a".repeat(length - "alias/".length()));
            }
            case 2 -> {
                List<String> parts = new ArrayList<>(List.of(keyArn.split(":", 6)));
                // A valid ARN has exactly 6 parts.
                // At least 2 parts keep the "arn:" start, so the input is still read as an ARN, not a raw key ID.
                int count = random.nextBoolean() ? 2 + random.nextInt(4) : 7 + random.nextInt(3);
                while (parts.size() > count) {
                    parts.remove(parts.size() - 1);
                }
                while (parts.size() < count) {
                    parts.add(lowercaseWord(random));
                }
                yield new Example<>(count + "-part ARN", String.join(":", parts));
            }
            case 3 -> {
                String[] parts = keyArn.split(":", 6);
                // Partition, service, Region and account must not be empty.
                int emptied = 1 + random.nextInt(4);
                parts[emptied] = "";
                yield new Example<>("empty ARN part " + emptied, String.join(":", parts));
            }
            case 4 -> {
                String service = "x" + lowercaseWord(random);
                yield new Example<>("service " + service,
                    "arn:aws:" + service + ":" + region + ":" + account + ":key/" + keyId);
            }
            default -> {
                String type = "x" + lowercaseWord(random);
                yield new Example<>("ARN resource " + type, arn.prefix() + type + "/" + keyId);
            }
        }));
        return examples;
    }

    /** Grant token lists that KMS accepts: at most 10 tokens, each 1 to 8192 characters. */
    public static List<Example<List<String>>> validGrantTokenLists() {
        return validGrantTokenLists(Fuzz.configured());
    }

    static List<Example<List<String>>> validGrantTokenLists(Fuzz fuzz) {
        List<Example<List<String>>> examples = new ArrayList<>(List.of(
            new Example<>("10 tokens of length 1", tokens(MAX_GRANT_TOKENS, 1)),
            new Example<>("10 tokens of length 8192", tokens(MAX_GRANT_TOKENS, MAX_GRANT_TOKEN_LENGTH))));
        examples.addAll(fuzz.examples("validGrantTokenLists", random -> {
            int count = random.nextInt(MAX_GRANT_TOKENS + 1);
            int length = 1 + random.nextInt(MAX_GRANT_TOKEN_LENGTH);
            return new Example<>(count + " tokens of length " + length, tokens(count, length));
        }));
        return examples;
    }

    /** Grant token lists that break one KMS limit: too many tokens, an empty token, or a token that is too long. */
    public static List<Example<List<String>>> invalidGrantTokenLists() {
        return invalidGrantTokenLists(Fuzz.configured());
    }

    static List<Example<List<String>>> invalidGrantTokenLists(Fuzz fuzz) {
        List<Example<List<String>>> examples = new ArrayList<>(List.of(
            new Example<>("11 tokens", tokens(MAX_GRANT_TOKENS + 1, 1)),
            new Example<>("an empty token", List.of("")),
            new Example<>("a token of length 8193", List.of("a".repeat(MAX_GRANT_TOKEN_LENGTH + 1)))));
        examples.addAll(fuzz.examples("invalidGrantTokenLists", random -> switch (random.nextInt(3)) {
            case 0 -> {
                int count = MAX_GRANT_TOKENS + 1 + random.nextInt(20);
                yield new Example<>(count + " tokens", tokens(count, 1));
            }
            case 1 -> {
                List<String> withEmpty = new ArrayList<>(tokens(random.nextInt(MAX_GRANT_TOKENS), 1));
                withEmpty.add(random.nextInt(withEmpty.size() + 1), "");
                yield new Example<>("an empty token among " + withEmpty.size(), withEmpty);
            }
            default -> {
                int length = MAX_GRANT_TOKEN_LENGTH + 1 + random.nextInt(4096);
                yield new Example<>("a token of length " + length, List.of("a".repeat(length)));
            }
        }));
        return examples;
    }

    /** {@code count} different tokens of {@code length} characters each. */
    private static List<String> tokens(int count, int length) {
        return IntStream.range(0, count)
            .mapToObj(i -> String.valueOf((char) ('a' + i % 26)).repeat(length))
            .toList();
    }

    private static String uuid(Random random) {
        return new UUID(random.nextLong(), random.nextLong()).toString();
    }

    private static String aliasName(Random random) {
        String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
        StringBuilder name = new StringBuilder();
        int length = 1 + random.nextInt(64);
        for (int i = 0; i < length; i++) {
            name.append(characters.charAt(random.nextInt(characters.length())));
        }
        return name.toString();
    }

    private static String lowercaseWord(Random random) {
        StringBuilder word = new StringBuilder();
        int length = 1 + random.nextInt(8);
        for (int i = 0; i < length; i++) {
            word.append((char) ('a' + random.nextInt(26)));
        }
        return word.toString();
    }

    /** The parts of {@code arn:<partition>:kms:<Region>:<account>:key/<key ID>} that the examples reuse. */
    private record KeyArn(String prefix, String region, String account, String keyId) {
        static KeyArn parse(String keyArn) {
            String[] parts = keyArn.split(":", 6);
            if (parts.length != 6 || !parts[0].equals("arn") || !parts[2].equals("kms")
                    || !parts[5].startsWith("key/")) {
                throw new IllegalArgumentException("not a KMS key ARN: " + keyArn);
            }
            String prefix = String.join(":", parts[0], parts[1], parts[2], parts[3], parts[4]) + ":";
            return new KeyArn(prefix, parts[3], parts[4], parts[5].substring("key/".length()));
        }
    }
}
