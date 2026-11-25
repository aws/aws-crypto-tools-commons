package aws.cryptography.testserver.tests;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.IntStream;

/**
 * Valid and invalid KMS inputs that any test that configures AWS KMS can reuse,
 * such as the AWS KMS keyring tests or an ESDK test that builds a KMS keyring.
 *
 * <p>Each list has fixed examples, each with a name for the test report.
 * When TESTSERVER_FUZZ is set, each list also gets random examples from the rule of the same name in
 * {@link KmsFuzzRules}. {@link Fuzz} says how to set it.
 * The rules come from the KMS documentation and from aws-kms-key-arn.md in the specification.
 */
public final class KmsFixtures {

    static final int MAX_IDENTIFIER_LENGTH = 2048;
    static final int MAX_GRANT_TOKENS = 10;
    static final int MAX_GRANT_TOKEN_LENGTH = 8192;

    private static final String ALIAS = "alias/x";

    private KmsFixtures() {
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
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("key ARN", keyArn),
            new Example<>("alias ARN", arn.prefix() + ALIAS),
            new Example<>("raw key ID", arn.keyId()),
            new Example<>("raw alias", ALIAS)));
        examples.addAll(fuzz.examples("validKmsIdentifiers", KmsFuzzRules.validKmsIdentifiers(keyArn)));
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
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
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
        examples.addAll(fuzz.examples("invalidKmsIdentifiers", KmsFuzzRules.invalidKmsIdentifiers(keyArn)));
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
        examples.addAll(fuzz.examples("validGrantTokenLists", KmsFuzzRules.validGrantTokenLists()));
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
        examples.addAll(fuzz.examples("invalidGrantTokenLists", KmsFuzzRules.invalidGrantTokenLists()));
        return examples;
    }

    /**
     * KeyIds for a KMS reply that are not any form of KMS identifier.
     *
     * @param keyArn the key ARN that the cut ARN comes from
     */
    public static List<Example<String>> garbageReplyKeyIds(String keyArn) {
        return garbageReplyKeyIds(keyArn, Fuzz.configured());
    }

    static List<Example<String>> garbageReplyKeyIds(String keyArn, Fuzz fuzz) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        String fivePartArn = "arn:aws:kms:" + arn.region() + ":" + arn.account();
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("foo/bar", "foo/bar"),
            new Example<>(fivePartArn, fivePartArn)));
        examples.addAll(fuzz.examples("garbageReplyKeyIds", KmsFuzzRules.garbageReplyKeyIds(keyArn)));
        return examples;
    }

    /** KeyIds for a KMS reply that are KMS identifiers, but not key ARNs: the raw key ID and an alias ARN. */
    public static List<Example<String>> nonArnReplyKeyIds(String keyArn) {
        return nonArnReplyKeyIds(keyArn, Fuzz.configured());
    }

    static List<Example<String>> nonArnReplyKeyIds(String keyArn, Fuzz fuzz) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        String aliasArn = arn.prefix() + ALIAS;
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>(arn.keyId(), arn.keyId()),
            new Example<>(aliasArn, aliasArn)));
        examples.addAll(fuzz.examples("nonArnReplyKeyIds", KmsFuzzRules.nonArnReplyKeyIds(keyArn)));
        return examples;
    }

    /** Encrypted data key provider IDs that are not exactly "aws-kms". */
    public static List<Example<String>> otherProviderIds() {
        return otherProviderIds(Fuzz.configured());
    }

    static List<Example<String>> otherProviderIds(Fuzz fuzz) {
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("AWS-KMS", "AWS-KMS"),
            new Example<>("raw-aes", "raw-aes")));
        examples.addAll(fuzz.examples("otherProviderIds", KmsFuzzRules.otherProviderIds()));
        return examples;
    }

    /** Key ARNs for keys other than {@code keyArn}, including {@code keyArn} with its key ID in upper case. */
    public static List<Example<String>> otherProviderInfos(String keyArn) {
        return otherProviderInfos(keyArn, Fuzz.configured());
    }

    static List<Example<String>> otherProviderInfos(String keyArn, Fuzz fuzz) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        String otherKeyArn = arn.prefix() + "key/00000000-0000-0000-0000-000000000000";
        String upperKeyId = arn.prefix() + "key/" + arn.keyId().toUpperCase(Locale.ROOT);
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>(otherKeyArn, otherKeyArn),
            new Example<>(upperKeyId, upperKeyId)));
        examples.addAll(fuzz.examples("otherProviderInfos", KmsFuzzRules.otherProviderInfos(keyArn)));
        return examples;
    }

    /** Encrypted data key provider info that is not a KMS ARN. */
    public static List<Example<byte[]>> nonArnProviderInfos(String keyArn) {
        return nonArnProviderInfos(keyArn, Fuzz.configured());
    }

    static List<Example<byte[]>> nonArnProviderInfos(String keyArn, Fuzz fuzz) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        List<Example<byte[]>> examples = new ArrayList<>(List.of(
            new Example<>("non-UTF-8 bytes", new byte[] {(byte) 0xFF, (byte) 0xFE}),
            new Example<>("not-an-arn", "not-an-arn".getBytes(StandardCharsets.UTF_8)),
            new Example<>("raw key id", arn.keyId().getBytes(StandardCharsets.UTF_8))));
        examples.addAll(fuzz.examples("nonArnProviderInfos", KmsFuzzRules.nonArnProviderInfos()));
        return examples;
    }

    /** Plaintext lengths for a KMS reply that do not match {@code dataKeyLength}: one byte short and one byte long. */
    public static List<Example<Integer>> wrongPlaintextLengths(int dataKeyLength) {
        return wrongPlaintextLengths(dataKeyLength, Fuzz.configured());
    }

    static List<Example<Integer>> wrongPlaintextLengths(int dataKeyLength, Fuzz fuzz) {
        List<Example<Integer>> examples = new ArrayList<>(List.of(
            new Example<>(String.valueOf(dataKeyLength - 1), dataKeyLength - 1),
            new Example<>(String.valueOf(dataKeyLength + 1), dataKeyLength + 1)));
        examples.addAll(fuzz.examples("wrongPlaintextLengths", KmsFuzzRules.wrongPlaintextLengths(dataKeyLength)));
        return examples;
    }

    /** {@code count} different tokens of {@code length} characters each. */
    static List<String> tokens(int count, int length) {
        return IntStream.range(0, count)
            .mapToObj(i -> String.valueOf((char) ('a' + i % 26)).repeat(length))
            .toList();
    }
}
