package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.KmsKeys.KMS_KEY_ARN;

import aws.cryptography.testserver.tests.ExpectedError;

/** The errors that an AWS KMS keyring raises for {@link KmsKeys#KMS_KEY_ARN}. */
final class KmsErrors {

    /** The error code that real KMS returns for a key it cannot find. FakeKms replies with it to make a call fail. */
    static final String KMS_ERROR_CODE = "NotFoundException";

    private static final String KMS_KEY_RESOURCE = "KmsKey:" + KMS_KEY_ARN;

    /** The error for a KMS call that failed with {@link #KMS_ERROR_CODE}. */
    static final ExpectedError KMS_CALL_FAILED_ERROR = ExpectedError.builder()
        .kind("ResourceNotFound")
        .service("kms")
        .resource(KMS_KEY_RESOURCE)
        .code(KMS_ERROR_CODE)
        .build();

    /** The error for a KMS reply that the keyring rejects, such as a bad KeyId or a plaintext of the wrong length. */
    static final ExpectedError REJECTED_KMS_REPLY_ERROR = ExpectedError.builder()
        .kind("Service")
        .service("kms")
        .resource(KMS_KEY_RESOURCE)
        .build();

    /**
     * The error for a real KMS call through a us-east-2 KMS client.
     * The kind is not checked, because it depends on what KMS in us-east-2 says about a us-west-2 key.
     */
    static final ExpectedError WRONG_REGION_KMS_ERROR = ExpectedError.builder()
        .service("kms")
        .resource(KMS_KEY_RESOURCE)
        .build();

    /** The error for an aws-kms EDK whose provider info is not a key ARN. */
    static final ExpectedError INVALID_PROVIDER_INFO_ERROR = ExpectedError.builder()
        .kind("Cryptographic")
        .build();

    private KmsErrors() {
    }
}
