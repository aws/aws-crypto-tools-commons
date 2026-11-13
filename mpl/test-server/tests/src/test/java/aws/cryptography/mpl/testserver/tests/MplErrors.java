package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.ErrorExpectation;
import aws.cryptography.testserver.tests.ErrorFields;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.Set;

/** {@link ErrorExpectation} for {@link MPLClientError}. */
final class MplErrors {

    /** The variants of the Rust MPL's {@code aws_crypto_mpl::Error}. */
    static final Set<String> KINDS = Set.of(
        "Validation", "InvalidMaterials", "EncryptionContextMismatch", "NoMatchingDataKey",
        "Cryptographic", "AccessDenied", "ResourceNotFound", "Throttling", "Conflict",
        "Service", "Dispatch", "Internal");

    /** The error for a keyring or CMM created with a bad setting, such as an empty key ID. */
    static final ExpectedError INVALID_CONFIGURATION_ERROR = ExpectedError.builder()
        .kind("Validation")
        .retryable(false)
        .build();

    /** The error for decryption materials that already hold a data key. */
    static final ExpectedError INVALID_MATERIALS_ERROR = ExpectedError.builder()
        .kind("InvalidMaterials")
        .build();

    /** The error when no encrypted data key (EDK) is for the keyring's key. */
    static final ExpectedError NO_MATCHING_DATA_KEY_ERROR = ExpectedError.builder()
        .kind("NoMatchingDataKey")
        .build();

    private MplErrors() {
    }

    /** Start checking the error {@code target} sent back. */
    static ErrorExpectation expectError(LanguageServerTarget target, MPLClientError e) {
        return ErrorExpectation.expectError(target, new ErrorFields(
            e.getKind(), e.getService(), e.getResource(), e.getCode(), e.isRetryable(),
            e.getRetryKind(), e.getConflictReason(), e.getMessage()), KINDS);
    }
}
