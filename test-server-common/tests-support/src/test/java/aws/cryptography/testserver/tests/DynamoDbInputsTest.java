package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.tests.DynamoDbInputs.DynamoDbNumber;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import org.junit.jupiter.api.Test;

class DynamoDbInputsTest {

    private static final Fuzz FUZZ = new Fuzz(500, 42, null);
    private static final BigDecimal SMALLEST = new BigDecimal("1E-130");
    private static final BigDecimal TOO_LARGE = new BigDecimal("1E126");

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(3, DynamoDbInputs.validNumbers(Fuzz.NONE).size());
        assertEquals(1, DynamoDbInputs.validNumberSets(Fuzz.NONE).size());
        assertEquals(1, DynamoDbInputs.numbersOutOfRange(Fuzz.NONE).size());
        assertEquals(1, DynamoDbInputs.malformedNumbers(Fuzz.NONE).size());
        assertEquals(1, DynamoDbInputs.stringSets(Fuzz.NONE).size());
        assertEquals(1, DynamoDbInputs.binarySets(Fuzz.NONE).size());
        assertEquals(1, DynamoDbInputs.attributeNames(Fuzz.NONE).size());
    }

    @Test
    void everyValidNumberNormalizesToItsExpectedForm() {
        for (Example<DynamoDbNumber> valid : DynamoDbInputs.validNumbers(FUZZ)) {
            assertEquals(normalized(valid.value().text()), valid.value().normalized(), valid.name());
        }
    }

    @Test
    void everyNumberSetHasDifferentValidMembers() {
        for (Example<List<DynamoDbNumber>> set : DynamoDbInputs.validNumberSets(FUZZ)) {
            List<String> normalized = set.value().stream().map(DynamoDbNumber::text).map(DynamoDbInputsTest::normalized).toList();
            assertEquals(set.value().stream().map(DynamoDbNumber::normalized).toList(), normalized, set.name());
            assertEquals(normalized.size(), new HashSet<>(normalized).size(), set.name() + ": " + normalized);
        }
    }

    @Test
    void everyOutOfRangeNumberIsWellFormedButBreaksALimit() {
        for (Example<String> invalid : DynamoDbInputs.numbersOutOfRange(FUZZ)) {
            BigDecimal number = new BigDecimal(invalid.value()).abs().stripTrailingZeros();
            assertTrue(number.precision() > 38 || number.compareTo(SMALLEST) < 0 || number.compareTo(TOO_LARGE) >= 0,
                invalid.name() + ": " + invalid.value());
        }
    }

    @Test
    void everyMalformedNumberIsNotANumber() {
        for (Example<String> invalid : DynamoDbInputs.malformedNumbers(FUZZ)) {
            assertFalse(parses(invalid.value()), invalid.name() + ": " + invalid.value());
        }
    }

    @Test
    void everyStringSetOrdersDifferentlyInUtf16AndUtf8() {
        for (Example<List<String>> set : DynamoDbInputs.stringSets(FUZZ)) {
            List<String> members = set.value();
            assertEquals(members.size(), new HashSet<>(members).size(), set.name());
            assertTrue(members.stream().allMatch(m -> !m.isEmpty() && isWellFormedUtf16(m)), set.name());
            List<String> utf16Order = members.stream().sorted().toList();
            List<String> utf8Order = members.stream().sorted(DynamoDbInputsTest::compareUtf8).toList();
            assertFalse(utf16Order.equals(utf8Order), set.name() + ": " + members);
        }
    }

    @Test
    void everyBinarySetHasAMemberThatStartsWithAnother() {
        for (Example<List<String>> set : DynamoDbInputs.binarySets(FUZZ)) {
            List<String> members = set.value();
            assertEquals(members.size(), new HashSet<>(members).size(), set.name());
            assertTrue(members.stream().allMatch(m -> !m.isEmpty() && m.length() % 2 == 0), set.name());
            assertTrue(members.stream().anyMatch(a -> members.stream().anyMatch(b -> !a.equals(b) && b.startsWith(a))),
                set.name() + ": " + members);
        }
    }

    @Test
    void everyAttributeNameHasMoreBytesThanCharacters() {
        for (Example<String> name : DynamoDbInputs.attributeNames(FUZZ)) {
            String value = name.value();
            assertTrue(isWellFormedUtf16(value), name.name());
            assertTrue(value.getBytes(StandardCharsets.UTF_8).length > value.codePointCount(0, value.length()),
                name.name());
            assertFalse(value.startsWith("aws_dbe_") || value.startsWith(":"), name.name());
        }
    }

    /**
     * DynamoDB's normalized form, worked out with BigDecimal instead of the code under test:
     * the plain decimal with no trailing zeros, and "0" for every zero.
     * Returns null for text that is not a number or breaks a DynamoDB limit.
     */
    private static String normalized(String text) {
        if (!parses(text)) {
            return null;
        }
        BigDecimal number = new BigDecimal(text).stripTrailingZeros();
        if (number.signum() == 0) {
            return "0";
        }
        BigDecimal magnitude = number.abs();
        if (number.precision() > 38 || magnitude.compareTo(SMALLEST) < 0 || magnitude.compareTo(TOO_LARGE) >= 0) {
            return null;
        }
        return number.toPlainString();
    }

    private static boolean parses(String text) {
        try {
            new BigDecimal(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static int compareUtf8(String a, String b) {
        return java.util.Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** No lone surrogate, so the string has a UTF-8 form. */
    private static boolean isWellFormedUtf16(String text) {
        return StandardCharsets.UTF_8.newEncoder().canEncode(text);
    }
}
