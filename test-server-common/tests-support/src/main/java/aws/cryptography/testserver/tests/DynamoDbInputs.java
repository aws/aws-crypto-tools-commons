package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * DynamoDB attribute values that any DB-ESDK test can reuse:
 * numbers in the many spellings that DynamoDB accepts, sets whose order a server must make canonical,
 * and attribute names with multi-byte characters.
 *
 * <p>The number rules are DynamoDB's: at most 38 significant digits,
 * and a magnitude from 1E-130 up to but not including 1E126.
 * ddb-attribute-serialization.md says that the DB-ESDK normalizes a number the way DynamoDB does.
 * The DB-ESDK's NormalizeNumber.dfy is the reference for the normalized form:
 * no exponent, no leading or trailing zeros, no "+", and "0" for every zero.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class DynamoDbInputs {

    private static final int MAX_SIGNIFICANT_DIGITS = 38;
    // A number is 0.D x 10^p, where D is its significant digits and has no leading zero.
    // DynamoDB accepts p from -129 (1E-130) to 126 (just under 1E126).
    private static final int MIN_POINT_POSITION = -129;
    private static final int MAX_POINT_POSITION = 126;

    private static final HexFormat HEX = HexFormat.of();

    /** "&" (U+0026), a BMP character above the surrogates (U+FF61), and an astral character (U+10002). */
    private static final List<String> ORDER_SENSITIVE_STRINGS = List.of("&", "\uFF61", "\uD800\uDC02");

    private DynamoDbInputs() {
    }

    /**
     * A number as a test sends it, and the normalized form that a server must decrypt it to.
     *
     * @param text the number as written, such as {@code 00012.34}
     * @param normalized the same number as NormalizeNumber.dfy writes it, such as {@code 12.34}
     */
    public record DynamoDbNumber(String text, String normalized) {
    }

    /** Numbers that DynamoDB accepts, each written in a form that a server must normalize. */
    public static List<Example<DynamoDbNumber>> validNumbers() {
        return validNumbers(Fuzz.configured());
    }

    static List<Example<DynamoDbNumber>> validNumbers(Fuzz fuzz) {
        List<Example<DynamoDbNumber>> examples = new ArrayList<>(List.of(
            new Example<>("leading zeros", new DynamoDbNumber("00012.34", "12.34")),
            new Example<>("negative zero", new DynamoDbNumber("-0", "0")),
            new Example<>("negative exponent", new DynamoDbNumber("123.456e-1", "12.3456"))));
        examples.addAll(fuzz.examples("validNumbers", random -> {
            DynamoDbNumber number = randomNumber(random);
            return new Example<>(number.text(), number);
        }));
        return examples;
    }

    /**
     * Number sets that DynamoDB accepts.
     * The members are different numbers, so they stay different after normalization.
     */
    public static List<Example<List<DynamoDbNumber>>> validNumberSets() {
        return validNumberSets(Fuzz.configured());
    }

    static List<Example<List<DynamoDbNumber>>> validNumberSets(Fuzz fuzz) {
        List<Example<List<DynamoDbNumber>>> examples = new ArrayList<>(List.of(
            // Sorted as text, the normalized members are 1, 10, 2.
            new Example<>("02 sorts after 10 once normalized", List.of(
                new DynamoDbNumber("1", "1"),
                new DynamoDbNumber("02", "2"),
                new DynamoDbNumber("10", "10")))));
        examples.addAll(fuzz.examples("validNumberSets", random -> {
            // Keyed by the normalized form, so "1" and "01.0" cannot both join.
            Map<String, DynamoDbNumber> members = new LinkedHashMap<>();
            int size = 1 + random.nextInt(10);
            while (members.size() < size) {
                DynamoDbNumber number = randomNumber(random);
                members.putIfAbsent(number.normalized(), number);
            }
            return new Example<>(size + " numbers", List.copyOf(members.values()));
        }));
        return examples;
    }

    /** Well-formed numbers that DynamoDB rejects: too many significant digits, or too large or too small. */
    public static List<Example<String>> numbersOutOfRange() {
        return numbersOutOfRange(Fuzz.configured());
    }

    static List<Example<String>> numbersOutOfRange(Fuzz fuzz) {
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("39 significant digits", "123456789.012345678901234567890123456789")));
        examples.addAll(fuzz.examples("numbersOutOfRange", random -> {
            boolean negative = random.nextBoolean();
            switch (random.nextInt(3)) {
                case 0: {
                    String digits = significantDigits(random, MAX_SIGNIFICANT_DIGITS + 1 + random.nextInt(20));
                    return new Example<>(digits.length() + " significant digits",
                        spell(random, negative, digits, pointPosition(random)));
                }
                case 1: {
                    int position = MAX_POINT_POSITION + 1 + random.nextInt(40);
                    return new Example<>("1E" + (position - 1) + " or larger",
                        spell(random, negative, significantDigits(random), position));
                }
                default: {
                    int position = MIN_POINT_POSITION - 1 - random.nextInt(40);
                    return new Example<>("smaller than 1E" + position,
                        spell(random, negative, significantDigits(random), position));
                }
            }
        }));
        return examples;
    }

    /** Text that is not a number at all. */
    public static List<Example<String>> malformedNumbers() {
        return malformedNumbers(Fuzz.configured());
    }

    static List<Example<String>> malformedNumbers(Fuzz fuzz) {
        List<Example<String>> examples = new ArrayList<>(List.of(
            new Example<>("two decimal points", "1.2.3")));
        // Each change below breaks the number on its own, whatever number it starts from.
        examples.addAll(fuzz.examples("malformedNumbers", random -> {
            String number = randomNumber(random).text();
            switch (random.nextInt(4)) {
                case 0: {
                    String withDots = number;
                    while (withDots.chars().filter(c -> c == '.').count() < 2) {
                        withDots = insert(withDots, random.nextInt(withDots.length() + 1), ".");
                    }
                    return new Example<>("two decimal points", withDots);
                }
                case 1: {
                    // Any letter but e, which starts an exponent.
                    String letters = "abcdfghijklmnopqrstuvwxyz";
                    String letter = String.valueOf(letters.charAt(random.nextInt(letters.length())));
                    return new Example<>("the letter " + letter,
                        insert(number, random.nextInt(number.length() + 1), letter));
                }
                case 2: {
                    String[] markers = {"e", "E", "e-", "e+"};
                    String marker = markers[random.nextInt(markers.length)];
                    return new Example<>("exponent " + marker + " with no digits",
                        number.replaceFirst("[eE].*$", "") + marker);
                }
                default: {
                    String[] signs = {"--", "++", "+-", "-+"};
                    String sign = signs[random.nextInt(signs.length)];
                    return new Example<>("sign " + sign, sign + number.replaceFirst("^[+-]", ""));
                }
            }
        }));
        return examples;
    }

    /**
     * String sets whose canonical order is UTF-16 binary order, which differs from UTF-8 byte order.
     * Every set has a member that starts with a BMP character above the surrogates, such as U+FF61,
     * and a member that starts with an astral character, such as U+10002.
     * UTF-16 puts the astral one first, and UTF-8 puts it last.
     */
    public static List<Example<List<String>>> stringSets() {
        return stringSets(Fuzz.configured());
    }

    static List<Example<List<String>>> stringSets(Fuzz fuzz) {
        List<Example<List<String>>> examples = new ArrayList<>(List.of(
            new Example<>("ASCII, U+FF61 and U+10002", ORDER_SENSITIVE_STRINGS)));
        examples.addAll(fuzz.examples("stringSets", random -> {
            Set<String> members = new LinkedHashSet<>();
            members.add(highBmpCharacter(random) + text(random, random.nextInt(6)));
            members.add(astralCharacter(random) + text(random, random.nextInt(6)));
            int size = 2 + random.nextInt(7);
            while (members.size() < size) {
                members.add(text(random, 1 + random.nextInt(6)));
            }
            return new Example<>(size + " strings", List.copyOf(members));
        }));
        return examples;
    }

    /**
     * Binary sets, each member as lowercase hex.
     * Every set has a member that starts with another member, such as 01 and 0100.
     * Lexicographic order puts the shorter one first, whatever bytes follow it.
     */
    public static List<Example<List<String>>> binarySets() {
        return binarySets(Fuzz.configured());
    }

    static List<Example<List<String>>> binarySets(Fuzz fuzz) {
        List<Example<List<String>>> examples = new ArrayList<>(List.of(
            new Example<>("01, 02 and 0100", List.of("01", "02", "0100"))));
        examples.addAll(fuzz.examples("binarySets", random -> {
            Set<String> members = new LinkedHashSet<>();
            byte[] shorter = bytes(random, 1 + random.nextInt(4));
            byte[] tail = bytes(random, 1 + random.nextInt(3));
            byte[] longer = new byte[shorter.length + tail.length];
            System.arraycopy(shorter, 0, longer, 0, shorter.length);
            System.arraycopy(tail, 0, longer, shorter.length, tail.length);
            members.add(HEX.formatHex(longer));
            members.add(HEX.formatHex(shorter));
            int size = 2 + random.nextInt(7);
            while (members.size() < size) {
                members.add(HEX.formatHex(bytes(random, 1 + random.nextInt(8))));
            }
            return new Example<>(size + " values", List.copyOf(members));
        }));
        return examples;
    }

    /**
     * Attribute names with a multi-byte UTF-8 character, so their length in bytes differs from their length in characters.
     * Every name starts with a non-ASCII character,
     * so no name starts with the reserved {@code aws_dbe_} prefix or the tests' unsigned prefix {@code :}.
     */
    public static List<Example<String>> attributeNames() {
        return attributeNames(Fuzz.configured());
    }

    static List<Example<String>> attributeNames(Fuzz fuzz) {
        List<Example<String>> examples = new ArrayList<>(List.of(
            // 4 characters and 5 UTF-8 bytes: the e with an accent is 2 bytes.
            new Example<>("caf\u00e9", "caf\u00e9")));
        examples.addAll(fuzz.examples("attributeNames", random -> {
            String name = nonAsciiCharacter(random) + text(random, random.nextInt(12));
            return new Example<>(name.codePointCount(0, name.length()) + "-character name", name);
        }));
        return examples;
    }

    /** A random number that DynamoDB accepts: zero one time in ten, otherwise any sign, digits and magnitude. */
    private static DynamoDbNumber randomNumber(Random random) {
        boolean negative = random.nextBoolean();
        if (random.nextInt(10) == 0) {
            return new DynamoDbNumber(spellZero(random, negative), "0");
        }
        String digits = significantDigits(random);
        int position = pointPosition(random);
        return new DynamoDbNumber(spell(random, negative, digits, position), normalize(negative, digits, position));
    }

    /** 1 to 38 random significant digits. */
    private static String significantDigits(Random random) {
        return significantDigits(random, 1 + random.nextInt(MAX_SIGNIFICANT_DIGITS));
    }

    /** {@code count} random digits that do not start or end with 0, so they are all significant. */
    private static String significantDigits(Random random, int count) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < count; i++) {
            boolean end = i == 0 || i == count - 1;
            digits.append((char) ((end ? '1' : '0') + random.nextInt(end ? 9 : 10)));
        }
        return digits.toString();
    }

    private static int pointPosition(Random random) {
        return MIN_POINT_POSITION + random.nextInt(MAX_POINT_POSITION - MIN_POINT_POSITION + 1);
    }

    /** 0.digits x 10^position, as NormalizeNumber.dfy writes it. */
    private static String normalize(boolean negative, String digits, int position) {
        String plain;
        if (position <= 0) {
            plain = "0." + "0".repeat(-position) + digits;
        } else if (position >= digits.length()) {
            plain = digits + "0".repeat(position - digits.length());
        } else {
            plain = digits.substring(0, position) + "." + digits.substring(position);
        }
        return (negative ? "-" : "") + plain;
    }

    /**
     * 0.digits x 10^position, written with a random exponent, random extra zeros at either end,
     * an optional "+" and an optional decimal point where one is allowed.
     */
    private static String spell(Random random, boolean negative, String digits, int position) {
        // The decimal point goes this many digits into the written digits; the exponent makes up the rest.
        int point = -3 + random.nextInt(digits.length() + 7);
        int exponent = position - point;
        String whole;
        String fraction;
        if (point <= 0) {
            whole = "";
            fraction = "0".repeat(-point) + digits;
        } else if (point >= digits.length()) {
            whole = digits + "0".repeat(point - digits.length());
            fraction = "";
        } else {
            whole = digits.substring(0, point);
            fraction = digits.substring(point);
        }
        whole = "0".repeat(random.nextInt(4)) + whole;
        fraction = fraction + "0".repeat(random.nextInt(4));
        String mantissa = fraction.isEmpty() && random.nextBoolean() ? whole : whole + "." + fraction;
        return sign(random, negative) + mantissa + exponent(random, exponent);
    }

    /** Zero written with 1 to 6 zero digits, an optional decimal point and any exponent. */
    private static String spellZero(Random random, boolean negative) {
        String whole = "0".repeat(random.nextInt(4));
        String fraction = "0".repeat((whole.isEmpty() ? 1 : 0) + random.nextInt(3));
        String mantissa = fraction.isEmpty() && random.nextBoolean() ? whole : whole + "." + fraction;
        return sign(random, negative) + mantissa + exponent(random, random.nextInt(2001) - 1000);
    }

    private static String sign(Random random, boolean negative) {
        return negative ? "-" : random.nextBoolean() ? "+" : "";
    }

    /** {@code e<exponent>} or {@code E<exponent>}, sometimes left out when the exponent is 0. */
    private static String exponent(Random random, int exponent) {
        if (exponent == 0 && random.nextBoolean()) {
            return "";
        }
        String marker = random.nextBoolean() ? "e" : "E";
        String sign = exponent < 0 ? "-" : random.nextBoolean() ? "+" : "";
        return marker + sign + Math.abs(exponent);
    }

    private static String insert(String text, int at, String inserted) {
        return text.substring(0, at) + inserted + text.substring(at);
    }

    /** {@code length} characters drawn from ASCII, Latin-1, Greek, CJK, private-use and astral characters. */
    private static String text(Random random, int length) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < length; i++) {
            text.append(switch (random.nextInt(4)) {
                case 0 -> String.valueOf((char) (0x21 + random.nextInt(0x5e)));
                case 1 -> nonAsciiCharacter(random);
                case 2 -> highBmpCharacter(random);
                default -> astralCharacter(random);
            });
        }
        return text.toString();
    }

    private static String nonAsciiCharacter(Random random) {
        return switch (random.nextInt(3)) {
            case 0 -> String.valueOf((char) (0xc0 + random.nextInt(0x17)));
            case 1 -> String.valueOf((char) (0x3b1 + random.nextInt(0x19)));
            default -> String.valueOf((char) (0x4e00 + random.nextInt(0x5200)));
        };
    }

    /** A private-use character from U+E000 to U+F8FF: above the surrogates, so UTF-16 sorts it after every astral character. */
    private static String highBmpCharacter(Random random) {
        return String.valueOf((char) (0xe000 + random.nextInt(0x1900)));
    }

    /** A character from U+10000 to U+1F64F, which UTF-16 writes as two surrogates. */
    private static String astralCharacter(Random random) {
        return Character.toString(0x10000 + random.nextInt(0xf650));
    }

    private static byte[] bytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
