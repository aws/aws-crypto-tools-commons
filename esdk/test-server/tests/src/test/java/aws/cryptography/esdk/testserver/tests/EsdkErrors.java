package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.testserver.tests.ErrorExpectation;
import aws.cryptography.testserver.tests.ErrorFields;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.Set;

/** {@link ErrorExpectation} for {@link ESDKClientError}. */
final class EsdkErrors {

    /** The variants of the Rust ESDK's {@code aws_esdk::Error}. */
    static final Set<String> KINDS = Set.of(
        "Validation", "InvalidMaterials", "EncryptionContextMismatch", "NoMatchingDataKey",
        "Cryptographic", "AccessDenied", "ResourceNotFound", "Throttling", "Conflict",
        "Service", "Dispatch", "Serialization", "Io", "Internal");

    private EsdkErrors() {
    }

    /** Start checking the error {@code target} sent back. */
    static ErrorExpectation expectError(LanguageServerTarget target, ESDKClientError e) {
        return ErrorExpectation.expectError(target, new ErrorFields(
            e.getKind(), e.getService(), e.getResource(), e.getCode(), e.isRetryable(),
            e.getRetryKind(), e.getConflictReason(), e.getMessage()), KINDS);
    }
}
