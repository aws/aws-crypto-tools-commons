package aws.cryptography.testserver.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * An expected error that tests can name once and reuse, for example:
 *
 * <pre>{@code
 * static final ExpectedError REJECTED_KMS_REPLY_ERROR = ExpectedError.builder()
 *     .kind("Service")
 *     .service("kms")
 *     .build();
 *
 * expectError(target, e).matches(REJECTED_KMS_REPLY_ERROR);
 * }</pre>
 *
 * <p>The builder methods are the same as {@link ErrorExpectation}'s,
 * and {@link ErrorExpectation#matches} runs them in order.
 */
public final class ExpectedError {

    private final List<Consumer<ErrorExpectation>> checks;

    private ExpectedError(List<Consumer<ErrorExpectation>> checks) {
        this.checks = List.copyOf(checks);
    }

    public static Builder builder() {
        return new Builder();
    }

    void checkAgainst(ErrorExpectation expectation) {
        checks.forEach(check -> check.accept(expectation));
    }

    public static final class Builder {

        private final List<Consumer<ErrorExpectation>> checks = new ArrayList<>();

        private Builder() {
        }

        public Builder kind(String expected) {
            checks.add(e -> e.kind(expected));
            return this;
        }

        @SafeVarargs
        public final Builder kind(Versioned<String>... expected) {
            checks.add(e -> e.kind(expected));
            return this;
        }

        public Builder service(String expected) {
            checks.add(e -> e.service(expected));
            return this;
        }

        @SafeVarargs
        public final Builder service(Versioned<String>... expected) {
            checks.add(e -> e.service(expected));
            return this;
        }

        public Builder resource(String expected) {
            checks.add(e -> e.resource(expected));
            return this;
        }

        @SafeVarargs
        public final Builder resource(Versioned<String>... expected) {
            checks.add(e -> e.resource(expected));
            return this;
        }

        public Builder code(String expected) {
            checks.add(e -> e.code(expected));
            return this;
        }

        @SafeVarargs
        public final Builder code(Versioned<String>... expected) {
            checks.add(e -> e.code(expected));
            return this;
        }

        public Builder retryable(boolean expected) {
            checks.add(e -> e.retryable(expected));
            return this;
        }

        @SafeVarargs
        public final Builder retryable(Versioned<Boolean>... expected) {
            checks.add(e -> e.retryable(expected));
            return this;
        }

        public Builder retryKind(String expected) {
            checks.add(e -> e.retryKind(expected));
            return this;
        }

        @SafeVarargs
        public final Builder retryKind(Versioned<String>... expected) {
            checks.add(e -> e.retryKind(expected));
            return this;
        }

        public Builder conflictReason(String expected) {
            checks.add(e -> e.conflictReason(expected));
            return this;
        }

        @SafeVarargs
        public final Builder conflictReason(Versioned<String>... expected) {
            checks.add(e -> e.conflictReason(expected));
            return this;
        }

        /** See {@link ErrorExpectation#message(String)} for how braces match. */
        public Builder message(String expected) {
            checks.add(e -> e.message(expected));
            return this;
        }

        @SafeVarargs
        public final Builder message(Versioned<String>... expected) {
            checks.add(e -> e.message(expected));
            return this;
        }

        /** @throws IllegalStateException when nothing is expected, because then nothing would be checked */
        public ExpectedError build() {
            if (checks.isEmpty()) {
                throw new IllegalStateException("an ExpectedError must expect at least one part of the error");
            }
            return new ExpectedError(checks);
        }
    }
}
