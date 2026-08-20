package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.LanguageServerRegistry;

import java.util.Optional;

/**
 * Resolves the AWS KMS runtime configuration — the {@code KMS_Test_Resources}
 * key ARNs and the AWS region — for the online, <strong>required</strong> KMS
 * round-trip scenarios from <em>runtime configuration only</em> (Requirement 14.7),
 * consistent with the runtime-configuration-only principle (Requirement 7.3) and
 * mirroring {@link LanguageServerRegistry}. Each value resolves from a system
 * property, then an environment variable, and finally falls back to the
 * <em>built-in default</em> for the shared {@code KMS_Test_Resources} deployed by
 * the {@code cdk/} stack ({@code EsdkTestServerKmsStack}) into the CI-resources
 * account. Those defaults (the deployed {@code CfnOutput} ARNs) are not secrets —
 * they are KMS key ARNs whose use is still authorized by AWS credentials — so a
 * developer or CI job with credentials for that account can run the KMS scenarios
 * with no extra configuration, while any deployment into a different account
 * overrides them via the property/env keys below.
 *
 * <p>Configuration keys (system property, then environment variable, then the
 * built-in default), matching the design's Data Models: KMS runtime configuration:
 * <ul>
 *   <li>{@code esdk.testserver.kms.symmetricKeyArn} / {@code ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN}
 *       — the symmetric KMS key ({@code AwsKms})</li>
 *   <li>{@code esdk.testserver.kms.mrkArn} / {@code ESDK_TESTSERVER_KMS_MRK_ARN}
 *       — the multi-region KMS key ({@code AwsKmsMrk})</li>
 *   <li>{@code esdk.testserver.kms.mrk2Arn} / {@code ESDK_TESTSERVER_KMS_MRK2_ARN}
 *       — the second multi-region KMS key, the child of the
 *       {@code AwsKmsMrkMultiKeyring} (whose generator is the {@code mrkArn} key)</li>
 *   <li>{@code esdk.testserver.kms.rsaKeyArn} / {@code ESDK_TESTSERVER_KMS_RSA_KEY_ARN}
 *       — the asymmetric RSA KMS key ({@code AwsKmsRsa})</li>
 *   <li>{@code esdk.testserver.kms.region} / {@code ESDK_TESTSERVER_KMS_REGION}
 *       — the AWS region (default {@code us-west-2} when the config is otherwise
 *       complete but no region was supplied)</li>
 * </ul>
 *
 * <p>Because the ARNs default, the KMS scenarios always resolve a complete
 * configuration and are <strong>required</strong>: {@link
 * EsdkClientConfigs#scenarios()} always contributes them and a run does not pass
 * unless they run and pass (Requirements 14.8, 14.9). AWS credentials therefore
 * must be present — developer credentials locally, GitHub OIDC in CI — and
 * {@link #configureAwsRegion()} applies the resolved region to the ambient AWS
 * region provider chain of the Tests JVM.
 */
public final class KmsRuntimeConfig {

    /** Default AWS region when the KMS config is complete but no region is given. */
    public static final String DEFAULT_REGION = "us-west-2";

    /**
     * Built-in default ARNs for the shared {@code KMS_Test_Resources} deployed by
     * {@code cdk/} ({@code EsdkTestServerKmsStack}) into the CI-resources account
     * ({@code 370957321024}, region {@value #DEFAULT_REGION}). These are the
     * stack's {@code CfnOutput}s; they are KMS key ARNs (not secrets — their use
     * is still gated by AWS credentials). Override any of them via the
     * corresponding system property or environment variable when deploying the
     * stack into a different account/region.
     */
    public static final String DEFAULT_SYMMETRIC_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/d3c7fc4c-5e03-4186-9d8e-ac95a6dc2f34";
    public static final String DEFAULT_MRK_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/mrk-8cc58a2e31cd40d79acb422a2c6faac0";
    public static final String DEFAULT_MRK2_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/mrk-68ecfc6885db4dd1a79040f69bdd86fe";
    public static final String DEFAULT_RSA_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/7dc78563-40d1-46be-b406-865d8893cee9";

    public static final String SYMMETRIC_KEY_ARN_PROPERTY = "esdk.testserver.kms.symmetricKeyArn";
    public static final String SYMMETRIC_KEY_ARN_ENV = "ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN";
    public static final String MRK_ARN_PROPERTY = "esdk.testserver.kms.mrkArn";
    public static final String MRK_ARN_ENV = "ESDK_TESTSERVER_KMS_MRK_ARN";
    public static final String MRK2_ARN_PROPERTY = "esdk.testserver.kms.mrk2Arn";
    public static final String MRK2_ARN_ENV = "ESDK_TESTSERVER_KMS_MRK2_ARN";
    public static final String RSA_KEY_ARN_PROPERTY = "esdk.testserver.kms.rsaKeyArn";
    public static final String RSA_KEY_ARN_ENV = "ESDK_TESTSERVER_KMS_RSA_KEY_ARN";
    public static final String REGION_PROPERTY = "esdk.testserver.kms.region";
    public static final String REGION_ENV = "ESDK_TESTSERVER_KMS_REGION";

    private final String symmetricKeyArn;
    private final String mrkArn;
    private final String mrk2Arn;
    private final String rsaKeyArn;
    private final String region;

    private KmsRuntimeConfig(
            String symmetricKeyArn, String mrkArn, String mrk2Arn, String rsaKeyArn, String region) {
        this.symmetricKeyArn = symmetricKeyArn;
        this.mrkArn = mrkArn;
        this.mrk2Arn = mrk2Arn;
        this.rsaKeyArn = rsaKeyArn;
        this.region = region;
    }

    /** Resolve the KMS configuration from the current runtime (system property / env). */
    public static KmsRuntimeConfig fromRuntime() {
        String symmetric = resolve(SYMMETRIC_KEY_ARN_PROPERTY, SYMMETRIC_KEY_ARN_ENV).orElse(DEFAULT_SYMMETRIC_KEY_ARN);
        String mrk = resolve(MRK_ARN_PROPERTY, MRK_ARN_ENV).orElse(DEFAULT_MRK_ARN);
        String mrk2 = resolve(MRK2_ARN_PROPERTY, MRK2_ARN_ENV).orElse(DEFAULT_MRK2_ARN);
        String rsa = resolve(RSA_KEY_ARN_PROPERTY, RSA_KEY_ARN_ENV).orElse(DEFAULT_RSA_KEY_ARN);
        String region = resolve(REGION_PROPERTY, REGION_ENV).orElse(DEFAULT_REGION);
        return new KmsRuntimeConfig(symmetric, mrk, mrk2, rsa, region);
    }

    private static Optional<String> resolve(String property, String env) {
        String fromProperty = System.getProperty(property);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return Optional.of(fromProperty.trim());
        }
        String fromEnv = System.getenv(env);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return Optional.of(fromEnv.trim());
        }
        return Optional.empty();
    }

    public String symmetricKeyArn() {
        return symmetricKeyArn;
    }

    public String mrkArn() {
        return mrkArn;
    }

    public String mrk2Arn() {
        return mrk2Arn;
    }

    public String rsaKeyArn() {
        return rsaKeyArn;
    }

    public String region() {
        return region;
    }

    /**
     * Apply the resolved region to the ambient AWS region provider chain (the
     * {@code aws.region} system property) unless a region is already configured,
     * so anything in this JVM that reads the ambient region resolves the region
     * the Tests were given. A no-op when {@code AWS_REGION} / {@code aws.region}
     * is already set. (Each Language_Server subprocess resolves its own region
     * from its environment; the orchestrator launches them with credentials and
     * region in scope.)
     */
    public void configureAwsRegion() {
        boolean alreadyConfigured =
            (System.getProperty("aws.region") != null && !System.getProperty("aws.region").isBlank())
                || envPresent("AWS_REGION");
        if (!alreadyConfigured && region != null && !region.isBlank()) {
            System.setProperty("aws.region", region);
        }
    }

    private static boolean envPresent(String name) {
        String value = System.getenv(name);
        return value != null && !value.isBlank();
    }
}
