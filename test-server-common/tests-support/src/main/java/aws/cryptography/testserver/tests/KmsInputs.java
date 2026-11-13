package aws.cryptography.testserver.tests;

import java.util.List;
import java.util.stream.IntStream;

/**
 * Valid and invalid KMS inputs that any test that configures AWS KMS can reuse,
 * such as the AWS KMS keyring tests or an ESDK test that builds a KMS keyring.
 *
 * <p>Each list is a fixed set of examples, each with a name for the test report.
 * The rules come from the KMS documentation and from aws-kms-key-arn.md in the specification.
 */
public final class KmsInputs {

    /** One input and a short name that says what makes it valid or invalid. */
    public record Example<T>(String name, T value) {
        @Override
        public String toString() {
            return name;
        }
    }

    private static final String ALIAS = "alias/x";

    private KmsInputs() {
    }

    /**
     * Every form of KMS identifier that aws-kms-key-arn.md calls valid:
     * {@code keyArn} itself, its key ID, an alias ARN in the same account and Region, and a raw alias.
     *
     * @param keyArn a key ARN, such as {@code arn:aws:kms:us-west-2:111122223333:key/<key ID>}
     */
    public static List<Example<String>> validKmsIdentifiers(String keyArn) {
        KeyArn arn = KeyArn.parse(keyArn);
        return List.of(
            new Example<>("key ARN", keyArn),
            new Example<>("alias ARN", arn.prefix() + ALIAS),
            new Example<>("raw key ID", arn.keyId()),
            new Example<>("raw alias", ALIAS));
    }

    /**
     * KMS identifiers that aws-kms-key-arn.md does not call valid.
     * Each one is {@code keyArn} with one thing wrong, or a raw form that is close to valid.
     *
     * @param keyArn a key ARN, such as {@code arn:aws:kms:us-west-2:111122223333:key/<key ID>}
     */
    public static List<Example<String>> invalidKmsIdentifiers(String keyArn) {
        KeyArn arn = KeyArn.parse(keyArn);
        String keyId = arn.keyId();
        String region = arn.region();
        String account = arn.account();
        return List.of(
            new Example<>("non-ASCII character", keyArn.substring(0, keyArn.length() - 1) + "\u00e9"),
            // A raw alias that is valid apart from its length.
            new Example<>("2049 characters", "alias/" + "a".repeat(2049 - "alias/".length())),
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
            new Example<>("raw alias/", "alias/"));
    }

    /** Grant token lists that KMS accepts: at most 10 tokens, each 1 to 8192 characters. */
    public static List<Example<List<String>>> validGrantTokenLists() {
        return List.of(
            new Example<>("10 tokens of length 1", tokens(10, 1)),
            new Example<>("10 tokens of length 8192", tokens(10, 8192)));
    }

    /** Grant token lists that break one KMS limit: too many tokens, an empty token, or a token that is too long. */
    public static List<Example<List<String>>> invalidGrantTokenLists() {
        return List.of(
            new Example<>("11 tokens", tokens(11, 1)),
            new Example<>("an empty token", List.of("")),
            new Example<>("a token of length 8193", List.of("a".repeat(8193))));
    }

    /** {@code count} different tokens of {@code length} characters each. */
    private static List<String> tokens(int count, int length) {
        return IntStream.range(0, count)
            .mapToObj(i -> String.valueOf((char) ('a' + i)).repeat(length))
            .toList();
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
