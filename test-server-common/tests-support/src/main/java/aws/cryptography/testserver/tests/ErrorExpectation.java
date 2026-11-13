package aws.cryptography.testserver.tests;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.opentest4j.AssertionFailedError;

/**
 * Checks the parts of an error a server sent back, for example:
 *
 * <pre>{@code
 * ESDKClientError e = assertThrows(ESDKClientError.class, () -> decrypt(...));
 * expectError(target, e)
 *     .kind(v1("InvalidInput"), v2("MissingKeyring"))
 *     .service("kms")
 *     .message("must provide keyring to {OnEncrypt}");
 * }</pre>
 *
 * <p>Each call checks one part right away, and only when the server turned that check on
 * (see {@link ErrorCheckDeclarations}).
 * For a server that has not, the test still passes as long as the call failed.
 *
 * <p>The server's check version picks which expected value applies (see {@link Versioned}).
 * A plain value, like {@code .service("kms")}, applies at every version.
 * When the server's version is lower than every expected value's, the part is not checked.
 *
 * <p>Once a check is on, a server that sends nothing for that part fails it.
 */
public final class ErrorExpectation {

    // A name in braces, like {OnEncrypt}.
    private static final Pattern SLOT = Pattern.compile("\\{([A-Za-z0-9]+)}");

    private final LanguageServerTarget target;
    private final ErrorFields actual;
    private final Set<String> kinds;
    private final ErrorCheckDeclarations declarations;

    private ErrorExpectation(LanguageServerTarget target, ErrorFields actual, Set<String> kinds,
            ErrorCheckDeclarations declarations) {
        this.target = Objects.requireNonNull(target, "target");
        this.actual = Objects.requireNonNull(actual, "actual");
        this.kinds = Set.copyOf(kinds);
        this.declarations = Objects.requireNonNull(declarations, "declarations");
    }

    /**
     * Start checking the error {@code target} sent back.
     * Each library's tests wrap this with their own error type and kinds.
     *
     * @param kinds every kind the library has; an expected kind not in this set is a typo in the test
     */
    public static ErrorExpectation expectError(
            LanguageServerTarget target, ErrorFields actual, Set<String> kinds) {
        return new ErrorExpectation(target, actual, kinds, ErrorCheckDeclarations.shared());
    }

    /** {@link #expectError(LanguageServerTarget, ErrorFields, Set)} with the declarations given. */
    public static ErrorExpectation expectError(LanguageServerTarget target, ErrorFields actual,
            Set<String> kinds, ErrorCheckDeclarations declarations) {
        return new ErrorExpectation(target, actual, kinds, declarations);
    }

    public ErrorExpectation kind(String expected) {
        return kind(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation kind(Versioned<String>... expected) {
        for (Versioned<String> value : expected) {
            if (!kinds.contains(value.value())) {
                throw new IllegalArgumentException("unknown error kind '" + value.value()
                    + "'; the kinds are " + kinds);
            }
        }
        return check("kind", actual.kind(), expected, Objects::equals);
    }

    public ErrorExpectation service(String expected) {
        return service(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation service(Versioned<String>... expected) {
        return check("service", actual.service(), expected, Objects::equals);
    }

    public ErrorExpectation resource(String expected) {
        return resource(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation resource(Versioned<String>... expected) {
        return check("resource", actual.resource(), expected, Objects::equals);
    }

    public ErrorExpectation code(String expected) {
        return code(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation code(Versioned<String>... expected) {
        return check("code", actual.code(), expected, Objects::equals);
    }

    public ErrorExpectation retryable(boolean expected) {
        return retryable(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation retryable(Versioned<Boolean>... expected) {
        return check("retryable", actual.retryable(), expected, Objects::equals);
    }

    public ErrorExpectation retryKind(String expected) {
        return retryKind(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation retryKind(Versioned<String>... expected) {
        return check("retryKind", actual.retryKind(), expected, Objects::equals);
    }

    public ErrorExpectation conflictReason(String expected) {
        return conflictReason(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation conflictReason(Versioned<String>... expected) {
        return check("conflictReason", actual.conflictReason(), expected, Objects::equals);
    }

    /**
     * The message must contain {@code expected}.
     * A name in braces matches that name in any language's style:
     * {@code {OnEncrypt}} matches {@code OnEncrypt}, {@code onEncrypt},
     * {@code on_encrypt} and {@code on-encrypt}.
     * Text outside braces must match exactly.
     */
    public ErrorExpectation message(String expected) {
        return message(Versioned.v1(expected));
    }

    @SafeVarargs
    public final ErrorExpectation message(Versioned<String>... expected) {
        return check("message", actual.message(), expected, ErrorExpectation::messageMatches);
    }

    /** Check every part {@code expected} names. */
    public ErrorExpectation matches(ExpectedError expected) {
        expected.checkAgainst(this);
        return this;
    }

    private <T> ErrorExpectation check(
            String check, T got, Versioned<T>[] expected, BiPredicate<T, T> matches) {
        if (expected.length == 0) {
            throw new IllegalArgumentException("expected at least one " + check);
        }
        Set<Integer> versions = new HashSet<>();
        for (Versioned<T> value : expected) {
            if (!versions.add(value.since())) {
                throw new IllegalArgumentException(
                    "two expected " + check + " values for version " + value.since());
            }
        }

        OptionalInt serverVersion = declarations.version(target, check);
        if (serverVersion.isEmpty()) {
            return this;
        }
        Optional<Versioned<T>> applies = Arrays.stream(expected)
            .filter(value -> value.since() <= serverVersion.getAsInt())
            .max(Comparator.comparingInt(Versioned::since));
        if (applies.isEmpty()) {
            return this;
        }

        T want = applies.get().value();
        String where = target + " error " + check + " (version " + serverVersion.getAsInt() + ")";
        if (got == null) {
            throw new AssertionFailedError(where + ": expected " + want + " but the server sent none");
        }
        if (!matches.test(want, got)) {
            throw new AssertionFailedError(where + ": expected " + want + " but got " + got, want, got);
        }
        return this;
    }

    /**
     * Whether {@code message} contains {@code pattern}.
     * A name in braces matches with any case and with or without {@code _} or {@code -} between letters.
     */
    static boolean messageMatches(String pattern, String message) {
        StringBuilder regex = new StringBuilder();
        Matcher slot = SLOT.matcher(pattern);
        int literalStart = 0;
        while (slot.find()) {
            regex.append(Pattern.quote(pattern.substring(literalStart, slot.start())));
            String name = slot.group(1);
            regex.append("(?i:");
            for (int i = 0; i < name.length(); i++) {
                if (i > 0) {
                    regex.append("[_-]?");
                }
                regex.append(Pattern.quote(String.valueOf(name.charAt(i))));
            }
            regex.append(')');
            literalStart = slot.end();
        }
        regex.append(Pattern.quote(pattern.substring(literalStart)));
        return Pattern.compile(regex.toString()).matcher(message).find();
    }
}
