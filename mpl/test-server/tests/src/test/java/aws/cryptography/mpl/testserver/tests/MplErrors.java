package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.ErrorExpectation;
import aws.cryptography.testserver.tests.ErrorFields;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.Set;

/** {@link ErrorExpectation} for {@link MPLClientError}. */
final class MplErrors {

    /** The variants of the Rust MPL's {@code aws_crypto_mpl::Error}. */
    static final Set<String> KINDS = Set.of(
        "Validation", "InvalidMaterials", "EncryptionContextMismatch", "NoMatchingDataKey",
        "Cryptographic", "AccessDenied", "ResourceNotFound", "Throttling", "Conflict",
        "Service", "Dispatch", "Internal");

    private MplErrors() {
    }

    /**
     * Start checking the error that {@code languageServer} sent back.
     * {@code languageServer} is the language whose MPL ran the call, such as Rust or Java.
     */
    static ErrorExpectation expectError(LanguageServerTarget languageServer, MPLClientError e) {
        return ErrorExpectation.expectError(languageServer, new ErrorFields(
            e.getKind(), e.getService(), e.getResource(), e.getCode(), e.isRetryable(),
            e.getRetryKind(), e.getConflictReason(), e.getMessage()), KINDS);
    }
}
