package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.KnownBugGate;
import org.junit.jupiter.api.function.Executable;

/**
 * The result of a check that an MPL call fails with an expected error, such as
 * {@link Keyring#onDecryptFailsWith}.
 *
 * <p>The call runs right away.
 * When the call does not fail with the expected error, this object keeps the AssertionError instead of throwing it.
 * That lets a test name the known bug that breaks the check, after the check:
 * <pre>{@code
 * keyring.onDecryptFailsWith(materials, edks, expectedError)
 *     .unlessKnownBug("some-bug-id");
 * }</pre>
 * When the test does not call {@link #unlessKnownBug}, the {@link Mpl} throws the kept AssertionError
 * at the test's next MPL call, or when the test ends.
 */
final class FailureCheck {

    private final Mpl mpl;
    /** The error that the MPL raised, or null when the call did not raise one. */
    private final MPLClientError error;
    /** Why the check failed, or null when it passed. */
    private final AssertionError failure;

    private FailureCheck(Mpl mpl, MPLClientError error, AssertionError failure) {
        this.mpl = mpl;
        this.error = error;
        this.failure = failure;
    }

    /** Run {@code call} on {@code mpl}, and check that the MPL rejects it with any error. */
    static FailureCheck run(Mpl mpl, Executable call) {
        return run(mpl, call, null);
    }

    /**
     * Run {@code call} on {@code mpl}, and check that the MPL rejects it with {@code expected}.
     * When {@code expected} is null, any MPL error passes.
     */
    static FailureCheck run(Mpl mpl, Executable call, ExpectedError expected) {
        // A failure kept from an earlier check is thrown here, so this check cannot catch it.
        mpl.throwUnresolvedFailure();
        MPLClientError error = null;
        AssertionError failure = null;
        try {
            error = assertThrows(MPLClientError.class, call);
            if (expected != null) {
                MplErrors.expectError(mpl.languageServer(), error).matches(expected);
            }
        } catch (AssertionError e) {
            failure = e;
        }
        FailureCheck check = new FailureCheck(mpl, error, failure);
        if (failure != null) {
            mpl.keepUnresolved(check);
        }
        return check;
    }

    /**
     * Decide this check with the known bug {@code bugId}, which breaks it in some language's MPL.
     * When this language's bug-config.json lists {@code bugId}, a failed check skips the test.
     * A passed check then fails the test, because the bug-config.json entry is out of date.
     * For other languages, a failed check fails the test.
     */
    void unlessKnownBug(String bugId) {
        mpl.forgetUnresolved(this);
        KnownBugGate.gateDeclaredOutcome(bugId, mpl.languageServer(), failure);
    }

    /** The error that the MPL raised. Throws the check's failure if the check failed. */
    MPLClientError error() {
        mpl.forgetUnresolved(this);
        throwIfFailed();
        return error;
    }

    /** Throw the kept AssertionError, if the check failed. */
    void throwIfFailed() {
        if (failure != null) {
            throw failure;
        }
    }
}
