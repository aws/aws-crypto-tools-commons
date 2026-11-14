package aws.cryptography.testserver.tests;

/**
 * The parts of a library error a server sent back, in one shape for every library.
 * Each library's tests copy their generated error into this, for example
 * {@code ESDKClientError} for the ESDK.
 *
 * <p>A server leaves a field {@code null} when its library has no such part.
 * The formats follow the Rust ESDK and MPL errors:
 *
 * @param kind           the error variant, for example {@code AccessDenied}
 * @param service        the AWS service the failed call went to: {@code kms} or {@code dynamodb}
 * @param resource       what the caller must act on, as {@code Type:id}, for example
 *                       {@code KmsKey:arn:aws:kms:...}, {@code DynamoDbTable:my-table},
 *                       {@code BranchKey:my-branch-key}, {@code Keyring:my-keyring},
 *                       {@code Cmm:my-cmm}, or just {@code Cache}
 * @param code           the AWS service's error code, for example {@code AccessDeniedException}
 * @param retryable      whether making the same call again later could succeed
 * @param retryKind      how to back off: {@code transient}, {@code throttling},
 *                       {@code server}, or {@code client}
 * @param conflictReason why a request conflicts: {@code AlreadyExists} or
 *                       {@code ConcurrentModification}
 * @param message        the error message
 */
public record ErrorFields(
    String kind,
    String service,
    String resource,
    String code,
    Boolean retryable,
    String retryKind,
    String conflictReason,
    String message
) {
}
