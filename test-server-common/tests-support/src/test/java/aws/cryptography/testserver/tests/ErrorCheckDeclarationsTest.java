package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;

class ErrorCheckDeclarationsTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:1");
    private static final LanguageServerTarget RUST =
        new LanguageServerTarget("rust", 1, "aws-crypto-tools-rust", ENDPOINT);
    private static final LanguageServerTarget JAVA =
        new LanguageServerTarget("java", 3, "aws-encryption-sdk-java", ENDPOINT);

    @Test
    void readsVersionsPerSource() {
        ErrorCheckDeclarations declarations = ErrorCheckDeclarations.parse(
            "rust:1:aws-crypto-tools-rust:kind=2;service=1;message=unsupported,"
                + "java:3:aws-encryption-sdk-java:kind=1");
        assertEquals(OptionalInt.of(2), declarations.version(RUST, "kind"));
        assertEquals(OptionalInt.of(1), declarations.version(RUST, "service"));
        assertEquals(OptionalInt.empty(), declarations.version(RUST, "message"));
        assertEquals(OptionalInt.empty(), declarations.version(RUST, "code"));
        assertEquals(OptionalInt.of(1), declarations.version(JAVA, "kind"));
    }

    @Test
    void nothingDeclaredMeansEveryCheckIsOff() {
        assertEquals(OptionalInt.empty(), ErrorCheckDeclarations.parse(null).version(RUST, "kind"));
        assertEquals(OptionalInt.empty(), ErrorCheckDeclarations.parse(" ").version(RUST, "kind"));
    }

    @Test
    void rejectsBadValues() {
        assertThrows(IllegalArgumentException.class,
            () -> ErrorCheckDeclarations.parse("rust:1:aws-crypto-tools-rust:kind=0"));
        assertThrows(IllegalArgumentException.class,
            () -> ErrorCheckDeclarations.parse("rust:1:aws-crypto-tools-rust:kind=yes"));
        assertThrows(IllegalArgumentException.class,
            () -> ErrorCheckDeclarations.parse("rust:1:kind=1"));
        assertThrows(IllegalArgumentException.class, () -> ErrorCheckDeclarations.parse(
            "rust:1:aws-crypto-tools-rust:kind=1,rust:1:aws-crypto-tools-rust:kind=2"));
    }
}
