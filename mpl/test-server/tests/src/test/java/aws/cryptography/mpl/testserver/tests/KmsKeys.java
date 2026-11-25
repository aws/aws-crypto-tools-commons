package aws.cryptography.mpl.testserver.tests;

/**
 * The real KMS key that the AWS KMS keyring tests use, and ARNs built from its account and Region.
 *
 * <p>The key is in the CI-resources account 370957321024, and the hierarchical keyring tests also use it.
 * It is a real resource, so the tests never make random versions of it.
 * THIS IS A TESTING RESOURCE. DO NOT USE IT IN A PRODUCTION ENVIRONMENT.
 */
final class KmsKeys {

    static final String REGION = "us-west-2";
    /** A Region that is not the key's. A KMS client for this Region cannot use the key. */
    static final String OTHER_REGION = "us-east-2";
    static final String ACCOUNT = "370957321024";
    static final String KEY_ID = "9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    static final String KMS_KEY_ARN = arn("key/" + KEY_ID);
    static final String ALIAS_ARN = arn("alias/x");
    /** A second real key in the same account. The MPL's own key store tests use it. */
    static final String SECOND_KEY_ARN = arn("key/bc127593-f7da-452c-a1f3-cd34c46f81f8");
    /** A real alias for SECOND_KEY_ARN. */
    static final String SECOND_KEY_ALIAS_ARN = arn("alias/postalHorn");
    /** A well-formed key ARN for a key other than KMS_KEY_ARN. */
    static final String OTHER_KEY_ARN = arn("key/00000000-0000-0000-0000-000000000000");

    private KmsKeys() {
    }

    /** The ARN of {@code resource}, such as {@code key/<key ID>}, in the key's account and Region. */
    static String arn(String resource) {
        return "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":" + resource;
    }
}
