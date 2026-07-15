package aws.cryptography.esdk.testserver.tests;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Resolves the AWS KMS runtime configuration — the {@code KMS_Test_Resources}
 * key ARNs and the AWS region — for the online, credential-gated KMS round-trip
 * scenarios from <em>runtime configuration only</em> (Requirement 14.7),
 * consistent with the runtime-configuration-only principle (Requirement 7.3) and
 * mirroring {@link RuntimeEndpointConfig}. Values are never hardcoded; they
 * originate from the CDK stack's {@code CfnOutput}s and are supplied to the Tests
 * by CI (from repo variables/secrets) or by a developer's environment.
 *
 * <p>Configuration keys (system property, then environment variable), matching
 * the design's Data Models: KMS runtime configuration:
 * <ul>
 *   <li>{@code esdk.testserver.kms.symmetricKeyArn} / {@code ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN}
 *       — the symmetric KMS key ({@code AwsKms})</li>
 *   <li>{@code esdk.testserver.kms.mrkArn} / {@code ESDK_TESTSERVER_KMS_MRK_ARN}
 *       — the multi-region KMS key ({@code AwsKmsMrk})</li>
 *   <li>{@code esdk.testserver.kms.rsaKeyArn} / {@code ESDK_TESTSERVER_KMS_RSA_KEY_ARN}
 *       — the asymmetric RSA KMS key ({@code AwsKmsRsa})</li>
 *   <li>{@code esdk.testserver.kms.region} / {@code ESDK_TESTSERVER_KMS_REGION}
 *       — the AWS region (default {@code us-west-2} when the config is otherwise
 *       complete but no region was supplied)</li>
 * </ul>
 *
 * <p>The gate {@link #isKmsAvailable()} is satisfied only when a
 * <strong>complete</strong> {@link KmsRuntimeConfig} (all three key ARNs) is
 * present <em>and</em> AWS credentials are resolvable (Requirements 14.8, 14.9).
 * When either is absent the KMS scenarios are omitted from
 * {@link EsdkClientConfigs#scenarios()} so {@code MaterialsRoundTripTests} skips
 * them and the offline suite still passes with no AWS access.
 */
public final class KmsRuntimeConfig {

    /** Default AWS region when the KMS config is complete but no region is given. */
    public static final String DEFAULT_REGION = "us-west-2";

    public static final String SYMMETRIC_KEY_ARN_PROPERTY = "esdk.testserver.kms.symmetricKeyArn";
    public static final String SYMMETRIC_KEY_ARN_ENV = "ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN";
    public static final String MRK_ARN_PROPERTY = "esdk.testserver.kms.mrkArn";
    public static final String MRK_ARN_ENV = "ESDK_TESTSERVER_KMS_MRK_ARN";
    public static final String RSA_KEY_ARN_PROPERTY = "esdk.testserver.kms.rsaKeyArn";
    public static final String RSA_KEY_ARN_ENV = "ESDK_TESTSERVER_KMS_RSA_KEY_ARN";
    public static final String REGION_PROPERTY = "esdk.testserver.kms.region";
    public static final String REGION_ENV = "ESDK_TESTSERVER_KMS_REGION";

    private final String symmetricKeyArn;
    private final String mrkArn;
    private final String rsaKeyArn;
    private final String region;

    private KmsRuntimeConfig(String symmetricKeyArn, String mrkArn, String rsaKeyArn, String region) {
        this.symmetricKeyArn = symmetricKeyArn;
        this.mrkArn = mrkArn;
        this.rsaKeyArn = rsaKeyArn;
        this.region = region;
    }

    /** Resolve the KMS configuration from the current runtime (system property / env). */
    public static KmsRuntimeConfig fromRuntime() {
        String symmetric = resolve(SYMMETRIC_KEY_ARN_PROPERTY, SYMMETRIC_KEY_ARN_ENV).orElse(null);
        String mrk = resolve(MRK_ARN_PROPERTY, MRK_ARN_ENV).orElse(null);
        String rsa = resolve(RSA_KEY_ARN_PROPERTY, RSA_KEY_ARN_ENV).orElse(null);
        String region = resolve(REGION_PROPERTY, REGION_ENV).orElse(DEFAULT_REGION);
        return new KmsRuntimeConfig(symmetric, mrk, rsa, region);
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

    /**
     * @return {@code true} when all three KMS key ARNs are present (the region
     *     always has a default). A complete config is one half of the KMS gate;
     *     the other half is resolvable AWS credentials (see {@link
     *     #isKmsAvailable()}).
     */
    public boolean isComplete() {
        return symmetricKeyArn != null && mrkArn != null && rsaKeyArn != null;
    }

    public String symmetricKeyArn() {
        return symmetricKeyArn;
    }

    public String mrkArn() {
        return mrkArn;
    }

    public String rsaKeyArn() {
        return rsaKeyArn;
    }

    public String region() {
        return region;
    }

    /**
     * The KMS gate (Requirements 14.8, 14.9): KMS round-trip scenarios run only
     * when a complete {@link KmsRuntimeConfig} is present <em>and</em> AWS
     * credentials are resolvable. Absence of either => the scenarios are omitted
     * and the offline suite runs to a pass without AWS access.
     *
     * @return {@code true} when the KMS scenarios should be contributed and run.
     */
    public static boolean isKmsAvailable() {
        return fromRuntime().isComplete() && credentialsResolvable();
    }

    /**
     * Lightweight, non-network credentials check. Rather than call STS (which the
     * gate must not do), this inspects the standard AWS credential sources the
     * default provider chain would consult: explicit access-key env vars, an OIDC
     * web-identity token file (how the CI_Workflow's assumed role surfaces),
     * container/instance credential env hints, a named profile, or an
     * {@code ~/.aws} credentials/config file. Any one present => credentials are
     * considered resolvable; none present => skip (robust absence => skip).
     *
     * @return {@code true} when AWS credentials appear resolvable without a
     *     network call.
     */
    public static boolean credentialsResolvable() {
        if (envPresent("AWS_ACCESS_KEY_ID") || envPresent("AWS_SECRET_ACCESS_KEY")) {
            return true;
        }
        if (envPresent("AWS_WEB_IDENTITY_TOKEN_FILE") && envPresent("AWS_ROLE_ARN")) {
            return true;
        }
        if (envPresent("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            || envPresent("AWS_CONTAINER_CREDENTIALS_FULL_URI")) {
            return true;
        }
        if (envPresent("AWS_PROFILE")) {
            return true;
        }
        return awsSharedConfigFilePresent();
    }

    /**
     * Apply the resolved region to the ambient AWS region provider chain (the
     * {@code aws.region} system property) unless a region is already configured,
     * so an in-process Language_Server's {@code KmsClient.create()} — which reads
     * the ambient region — resolves the region the Tests were given. A no-op when
     * {@code AWS_REGION} / {@code aws.region} is already set. Only intended to be
     * called once the gate is satisfied.
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

    private static boolean awsSharedConfigFilePresent() {
        String home = System.getProperty("user.home");
        if (home == null || home.isBlank()) {
            return false;
        }
        Path awsDir = Paths.get(home, ".aws");
        return Files.isRegularFile(awsDir.resolve("credentials"))
            || Files.isRegularFile(awsDir.resolve("config"));
    }
}
