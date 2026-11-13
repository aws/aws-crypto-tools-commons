package aws.cryptography.testserver.tests;

import static aws.cryptography.testserver.tests.Versioned.v1;
import static aws.cryptography.testserver.tests.Versioned.v2;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

// Each test builds a server declaration by hand, then checks one error against it.
class ErrorExpectationTest {

    private static final LanguageServerTarget RUST =
        new LanguageServerTarget("rust", 1, "aws-crypto-tools-rust", URI.create("http://127.0.0.1:1"));
    private static final Set<String> KINDS = Set.of("Validation", "InvalidInput", "MissingKeyring");

    private static ErrorFields error(String kind, String message) {
        return new ErrorFields(kind, "kms", null, null, false, null, null, message);
    }

    private static ErrorExpectation expect(String declared, ErrorFields actual) {
        return ErrorExpectation.expectError(
            RUST, actual, KINDS, ErrorCheckDeclarations.parse(declared));
    }

    @Test
    void checkOffPassesAnyValue() {
        assertDoesNotThrow(() -> expect(null, error("Validation", "x")).kind("MissingKeyring"));
        assertDoesNotThrow(() -> expect("rust:1:aws-crypto-tools-rust:kind=unsupported",
            error("Validation", "x")).kind("MissingKeyring"));
    }

    @Test
    void checkOnComparesValue() {
        String declared = "rust:1:aws-crypto-tools-rust:kind=1;service=1";
        assertDoesNotThrow(() -> expect(declared, error("Validation", "x"))
            .kind("Validation").service("kms"));
        assertThrows(AssertionFailedError.class,
            () -> expect(declared, error("Validation", "x")).kind("MissingKeyring"));
    }

    @Test
    void checkOnFailsWhenServerSendsNothing() {
        assertThrows(AssertionFailedError.class,
            () -> expect("rust:1:aws-crypto-tools-rust:kind=1", error(null, "x")).kind("Validation"));
    }

    @Test
    void serverVersionPicksExpectedValue() {
        ErrorFields old = error("InvalidInput", "x");
        ErrorFields current = error("MissingKeyring", "x");
        String atV1 = "rust:1:aws-crypto-tools-rust:kind=1";
        String atV3 = "rust:1:aws-crypto-tools-rust:kind=3";

        assertDoesNotThrow(() -> expect(atV1, old).kind(v1("InvalidInput"), v2("MissingKeyring")));
        assertThrows(AssertionFailedError.class,
            () -> expect(atV1, current).kind(v1("InvalidInput"), v2("MissingKeyring")));
        assertDoesNotThrow(() -> expect(atV3, current).kind(v1("InvalidInput"), v2("MissingKeyring")));
    }

    @Test
    void serverBelowEveryExpectedVersionIsNotChecked() {
        assertDoesNotThrow(() -> expect("rust:1:aws-crypto-tools-rust:kind=1",
            error("Validation", "x")).kind(v2("MissingKeyring")));
    }

    @Test
    void unknownKindIsATestBugEvenWithTheCheckOff() {
        assertThrows(IllegalArgumentException.class,
            () -> expect(null, error("Validation", "x")).kind("Validaton"));
    }

    @Test
    void twoValuesForOneVersionIsATestBug() {
        assertThrows(IllegalArgumentException.class,
            () -> expect(null, error("Validation", "x")).service(v1("kms"), v1("dynamodb")));
    }

    @Test
    void nameInBracesMatchesAnyStyle() {
        String pattern = "must provide keyring to {OnEncrypt}";
        assertTrue(ErrorExpectation.messageMatches(pattern, "must provide keyring to OnEncrypt"));
        assertTrue(ErrorExpectation.messageMatches(pattern, "must provide keyring to onEncrypt"));
        assertTrue(ErrorExpectation.messageMatches(pattern, "must provide keyring to on_encrypt"));
        assertTrue(ErrorExpectation.messageMatches(pattern, "must provide keyring to on-encrypt"));
        assertTrue(ErrorExpectation.messageMatches(pattern,
            "Validation: must provide keyring to on_encrypt (keyring my-keyring)"));
        assertFalse(ErrorExpectation.messageMatches(pattern, "must provide keyring to on_decrypt"));
    }

    @Test
    void textOutsideBracesMustMatchExactly() {
        assertFalse(ErrorExpectation.messageMatches("must provide keyring", "Must Provide Keyring"));
        assertTrue(ErrorExpectation.messageMatches("a.b (c)", "x a.b (c) y"));
        assertFalse(ErrorExpectation.messageMatches("a.b", "axb"));
    }
}
