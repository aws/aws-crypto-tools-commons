package aws.cryptography.esdk.testserver.tests;

import java.util.Optional;

/**
 * Resolves the AWS KMS Hierarchical keyring configuration — branch key id,
 * DynamoDB key store table + logical name, wrapping KMS key ARN, and branch-key
 * cache TTL — for the online hierarchical round-trip scenario. Each value comes
 * from a system property, then an environment variable, then a built-in default
 * (the property/env keys are the constants below). The scenario is online, so it
 * needs AWS credentials with KMS access to the wrapping key and DynamoDB read on
 * the key store table.
 */
public final class HierarchicalRuntimeConfig {

    /** Default AWS region when none is otherwise configured. */
    public static final String DEFAULT_REGION = "us-west-2";

    /**
     * Defaults for the shared branch key store (CI-resources account
     * {@code 370957321024}) — the canonical fixtures shared across the ESDK/MPL
     * test suites.
     */
    public static final String DEFAULT_BRANCH_KEY_ID = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
    public static final String DEFAULT_KEY_STORE_TABLE_NAME = "KeyStoreDdbTable";
    public static final String DEFAULT_LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    public static final String DEFAULT_KMS_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    public static final int DEFAULT_TTL_SECONDS = 600;

    public static final String BRANCH_KEY_ID_PROPERTY = "esdk.testserver.hierarchical.branchKeyId";
    public static final String BRANCH_KEY_ID_ENV = "ESDK_TESTSERVER_HIERARCHICAL_BRANCH_KEY_ID";
    public static final String KEY_STORE_TABLE_NAME_PROPERTY =
        "esdk.testserver.hierarchical.keyStoreTableName";
    public static final String KEY_STORE_TABLE_NAME_ENV =
        "ESDK_TESTSERVER_HIERARCHICAL_KEY_STORE_TABLE_NAME";
    public static final String LOGICAL_KEY_STORE_NAME_PROPERTY =
        "esdk.testserver.hierarchical.logicalKeyStoreName";
    public static final String LOGICAL_KEY_STORE_NAME_ENV =
        "ESDK_TESTSERVER_HIERARCHICAL_LOGICAL_KEY_STORE_NAME";
    public static final String KMS_KEY_ARN_PROPERTY = "esdk.testserver.hierarchical.kmsKeyArn";
    public static final String KMS_KEY_ARN_ENV = "ESDK_TESTSERVER_HIERARCHICAL_KMS_KEY_ARN";
    public static final String TTL_SECONDS_PROPERTY = "esdk.testserver.hierarchical.ttlSeconds";
    public static final String TTL_SECONDS_ENV = "ESDK_TESTSERVER_HIERARCHICAL_TTL_SECONDS";
    public static final String REGION_PROPERTY = "esdk.testserver.hierarchical.region";
    public static final String REGION_ENV = "ESDK_TESTSERVER_HIERARCHICAL_REGION";

    private final String branchKeyId;
    private final String keyStoreTableName;
    private final String logicalKeyStoreName;
    private final String kmsKeyArn;
    private final int ttlSeconds;
    private final String region;

    private HierarchicalRuntimeConfig(
        String branchKeyId,
        String keyStoreTableName,
        String logicalKeyStoreName,
        String kmsKeyArn,
        int ttlSeconds,
        String region) {
        this.branchKeyId = branchKeyId;
        this.keyStoreTableName = keyStoreTableName;
        this.logicalKeyStoreName = logicalKeyStoreName;
        this.kmsKeyArn = kmsKeyArn;
        this.ttlSeconds = ttlSeconds;
        this.region = region;
    }

    /** Resolve the hierarchical configuration from the current runtime (property / env). */
    public static HierarchicalRuntimeConfig fromRuntime() {
        String branchKeyId = resolve(BRANCH_KEY_ID_PROPERTY, BRANCH_KEY_ID_ENV)
            .orElse(DEFAULT_BRANCH_KEY_ID);
        String tableName = resolve(KEY_STORE_TABLE_NAME_PROPERTY, KEY_STORE_TABLE_NAME_ENV)
            .orElse(DEFAULT_KEY_STORE_TABLE_NAME);
        String logicalName = resolve(LOGICAL_KEY_STORE_NAME_PROPERTY, LOGICAL_KEY_STORE_NAME_ENV)
            .orElse(DEFAULT_LOGICAL_KEY_STORE_NAME);
        String kmsKeyArn = resolve(KMS_KEY_ARN_PROPERTY, KMS_KEY_ARN_ENV).orElse(DEFAULT_KMS_KEY_ARN);
        int ttlSeconds = resolve(TTL_SECONDS_PROPERTY, TTL_SECONDS_ENV)
            .map(Integer::parseInt)
            .orElse(DEFAULT_TTL_SECONDS);
        String region = resolve(REGION_PROPERTY, REGION_ENV).orElse(DEFAULT_REGION);
        return new HierarchicalRuntimeConfig(
            branchKeyId, tableName, logicalName, kmsKeyArn, ttlSeconds, region);
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

    public String branchKeyId() {
        return branchKeyId;
    }

    public String keyStoreTableName() {
        return keyStoreTableName;
    }

    public String logicalKeyStoreName() {
        return logicalKeyStoreName;
    }

    public String kmsKeyArn() {
        return kmsKeyArn;
    }

    public int ttlSeconds() {
        return ttlSeconds;
    }

    public String region() {
        return region;
    }

    /**
     * Apply the resolved region to the ambient AWS region provider chain (the
     * {@code aws.region} system property) unless a region is already configured, so
     * an in-process Language_Server's DynamoDB / KMS clients resolve the region the
     * Tests were given. A no-op when {@code AWS_REGION} / {@code aws.region} is set.
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
