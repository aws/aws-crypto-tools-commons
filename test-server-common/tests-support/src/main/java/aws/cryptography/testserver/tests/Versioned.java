package aws.cryptography.testserver.tests;

/**
 * An expected error value and the check version it starts at.
 *
 * <p>When a library changes an error, the test keeps the old value and adds the new one:
 * {@code .kind(v1("InvalidInput"), v2("MissingKeyring"))}.
 * A server at version 1 must send {@code InvalidInput}.
 * A server at version 2 or later must send {@code MissingKeyring}.
 *
 * @param since the first check version that expects {@code value}
 * @param value the expected value
 */
public record Versioned<T>(int since, T value) {

    public Versioned {
        if (since < 1) {
            throw new IllegalArgumentException("versions start at 1, got " + since);
        }
    }

    public static <T> Versioned<T> v1(T value) {
        return new Versioned<>(1, value);
    }

    public static <T> Versioned<T> v2(T value) {
        return new Versioned<>(2, value);
    }

    public static <T> Versioned<T> v3(T value) {
        return new Versioned<>(3, value);
    }
}
