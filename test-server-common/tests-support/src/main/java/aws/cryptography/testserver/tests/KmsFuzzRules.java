package aws.cryptography.testserver.tests;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.UUID;
import java.util.function.Function;

/**
 * How to make a random example for each list in {@link KmsFixtures}.
 *
 * <p>Each method has the name of the list it adds to.
 * A random example must follow the same rule as the list's fixed examples, whatever the random parts are.
 * {@link Fuzz} decides how many random examples each list gets, and with which seed.
 */
public final class KmsFuzzRules {

    private KmsFuzzRules() {
    }

    /** A random KMS identifier in one of the forms that aws-kms-key-arn.md calls valid. */
    public static Function<Random, Example<String>> validKmsIdentifiers(String keyArn) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        return random -> switch (random.nextInt(4)) {
            case 0 -> new Example<>("key ARN with a random key ID", arn.prefix() + "key/" + uuid(random));
            case 1 -> new Example<>("alias ARN with a random name", arn.prefix() + "alias/" + aliasName(random));
            case 2 -> new Example<>("random raw key ID", uuid(random));
            default -> new Example<>("random raw alias", "alias/" + aliasName(random));
        };
    }

    /** {@code keyArn} with one random change that breaks a rule in aws-kms-key-arn.md. */
    public static Function<Random, Example<String>> invalidKmsIdentifiers(String keyArn) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        String keyId = arn.keyId();
        String region = arn.region();
        String account = arn.account();
        return random -> switch (random.nextInt(6)) {
            case 0 -> {
                int at = random.nextInt(keyArn.length() + 1);
                yield new Example<>("non-ASCII character at " + at,
                    keyArn.substring(0, at) + (char) (0x80 + random.nextInt(0x700)) + keyArn.substring(at));
            }
            case 1 -> {
                int length = KmsFixtures.MAX_IDENTIFIER_LENGTH + 1 + random.nextInt(2048);
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
        };
    }

    /** A random grant token list within the KMS limits. */
    public static Function<Random, Example<List<String>>> validGrantTokenLists() {
        return random -> {
            int count = random.nextInt(KmsFixtures.MAX_GRANT_TOKENS + 1);
            int length = 1 + random.nextInt(KmsFixtures.MAX_GRANT_TOKEN_LENGTH);
            return new Example<>(count + " tokens of length " + length, KmsFixtures.tokens(count, length));
        };
    }

    /** A random grant token list that breaks one KMS limit. */
    public static Function<Random, Example<List<String>>> invalidGrantTokenLists() {
        return random -> switch (random.nextInt(3)) {
            case 0 -> {
                int count = KmsFixtures.MAX_GRANT_TOKENS + 1 + random.nextInt(20);
                yield new Example<>(count + " tokens", KmsFixtures.tokens(count, 1));
            }
            case 1 -> {
                List<String> withEmpty =
                    new ArrayList<>(KmsFixtures.tokens(random.nextInt(KmsFixtures.MAX_GRANT_TOKENS), 1));
                withEmpty.add(random.nextInt(withEmpty.size() + 1), "");
                yield new Example<>("an empty token among " + withEmpty.size(), withEmpty);
            }
            default -> {
                int length = KmsFixtures.MAX_GRANT_TOKEN_LENGTH + 1 + random.nextInt(4096);
                yield new Example<>("a token of length " + length, List.of("a".repeat(length)));
            }
        };
    }

    /** A random KeyId that is not any form of KMS identifier: a raw resource of an unknown type, or a cut ARN. */
    public static Function<Random, Example<String>> garbageReplyKeyIds(String keyArn) {
        return random -> {
            String keyId;
            if (random.nextBoolean()) {
                // The "x" start keeps the type from being key or alias.
                keyId = "x" + lowercaseWord(random) + "/" + lowercaseWord(random);
            } else {
                // A valid ARN has 6 parts. 2 to 5 parts keep the "arn:" start and drop the resource.
                String[] parts = keyArn.split(":", 6);
                keyId = String.join(":", List.of(parts).subList(0, 2 + random.nextInt(4)));
            }
            return new Example<>(keyId, keyId);
        };
    }

    /** A random raw key ID or alias ARN: a KMS identifier that is not a key ARN. */
    public static Function<Random, Example<String>> nonArnReplyKeyIds(String keyArn) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        return random -> {
            String keyId = random.nextBoolean() ? uuid(random) : arn.prefix() + "alias/" + aliasName(random);
            return new Example<>(keyId, keyId);
        };
    }

    /** A random provider ID that is not exactly "aws-kms". */
    public static Function<Random, Example<String>> otherProviderIds() {
        return random -> {
            String providerId;
            if (random.nextBoolean()) {
                // Letters only, so it is never "aws-kms".
                providerId = lowercaseWord(random);
            } else {
                // "aws-kms" with one letter in upper case.
                int[] letters = {0, 1, 2, 4, 5, 6};
                int at = letters[random.nextInt(letters.length)];
                providerId = "aws-kms".substring(0, at) + Character.toUpperCase("aws-kms".charAt(at))
                    + "aws-kms".substring(at + 1);
            }
            return new Example<>(providerId, providerId);
        };
    }

    /** A random key ARN for a key other than {@code keyArn}. */
    public static Function<Random, Example<String>> otherProviderInfos(String keyArn) {
        KmsKeyArn arn = KmsKeyArn.parse(keyArn);
        return random -> {
            String providerInfo = switch (random.nextInt(3)) {
                case 0 -> withOneLetterUpperCase(arn, random);
                case 1 -> otherAccount(arn, random);
                default -> arn.prefix() + "key/" + uuid(random);
            };
            return new Example<>(providerInfo, providerInfo);
        };
    }

    /** Random provider info that is not a KMS ARN: bytes that are not UTF-8, a word, or a raw key ID. */
    public static Function<Random, Example<byte[]>> nonArnProviderInfos() {
        return random -> switch (random.nextInt(3)) {
            case 0 -> {
                // 0xFF never appears in UTF-8.
                byte[] bytes = new byte[1 + random.nextInt(8)];
                bytes[0] = (byte) 0xFF;
                for (int i = 1; i < bytes.length; i++) {
                    bytes[i] = (byte) (0x80 + random.nextInt(0x80));
                }
                yield new Example<>("non-UTF-8 bytes", bytes);
            }
            case 1 -> {
                String word = lowercaseWord(random);
                yield new Example<>(word, word.getBytes(StandardCharsets.UTF_8));
            }
            default -> new Example<>("random raw key id",
                uuid(random).getBytes(StandardCharsets.UTF_8));
        };
    }

    /** A random data key length from 1 to twice {@code dataKeyLength}, other than {@code dataKeyLength}. */
    public static Function<Random, Example<Integer>> wrongPlaintextLengths(int dataKeyLength) {
        return random -> {
            int length = 1 + random.nextInt(2 * dataKeyLength - 1);
            if (length >= dataKeyLength) {
                length++;
            }
            return new Example<>(String.valueOf(length), length);
        };
    }

    /** {@code arn} with one lower-case letter of its key ID in upper case, or a random key ID if it has none. */
    private static String withOneLetterUpperCase(KmsKeyArn arn, Random random) {
        String keyId = arn.keyId();
        List<Integer> letters = new ArrayList<>();
        for (int i = 0; i < keyId.length(); i++) {
            if (Character.isLowerCase(keyId.charAt(i))) {
                letters.add(i);
            }
        }
        if (letters.isEmpty()) {
            return arn.prefix() + "key/" + uuid(random);
        }
        int at = letters.get(random.nextInt(letters.size()));
        return arn.prefix() + "key/" + keyId.substring(0, at)
            + keyId.substring(at, at + 1).toUpperCase(Locale.ROOT) + keyId.substring(at + 1);
    }

    /** {@code arn} in a random 12-digit account other than its own. */
    private static String otherAccount(KmsKeyArn arn, Random random) {
        String account;
        do {
            account = String.format(Locale.ROOT, "%012d", Math.floorMod(random.nextLong(), 1_000_000_000_000L));
        } while (account.equals(arn.account()));
        String prefix = arn.prefix();
        return prefix.substring(0, prefix.length() - arn.account().length() - 1) + account + ":key/" + arn.keyId();
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
}
