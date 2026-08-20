package aws.cryptography.dbesdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientOutput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * General test helpers shared by every DB-ESDK cross-language test class
 * ({@link TamperTests}, {@link DbeRoundTripTests}, and future additions).
 *
 * <p>Everything here is <em>reusable across scenarios</em>. Scenario-specific
 * state — e.g. the tamper suite's pre-encrypted baseline cache — lives inside
 * that scenario's test class, not here.
 *
 * <p>What lives here:
 * <ul>
 *   <li>{@link #pairs()} — the single {@code @MethodSource} provider for the
 *       cross-language pair matrix. Delegates to
 *       {@link LanguageServerRegistry#shared() the shared registry}, so every
 *       test class ends up iterating the exact same {@code List<TargetPair>}
 *       for the run.</li>
 *   <li>Attribute-name constants ({@link #PK}, {@link #SECRET}, {@link #PUBLIC},
 *       {@link #HEAD}, {@link #FOOT}, {@link #TABLE}) used by all tests to
 *       stay consistent with the schema.</li>
 *   <li>{@link #standardActions()} — the SIGN_ONLY / ENCRYPT_AND_SIGN /
 *       SIGN_ONLY action map used across the suite.</li>
 *   <li>{@link #canonicalPlaintext()} — the shared 3-attribute plaintext used
 *       for encrypt-then-decrypt across every test.</li>
 *   <li>{@link #newKmsClient(DBESDKTestServerClient, String, String, Map, List)}
 *       — build a DBE client pinned to the ESDK-shared AWS-KMS symmetric key
 *       (the only keyring both sides of a cross-language pair can share
 *       today). Tests wanting a different keyring build their own config
 *       inline.</li>
 *   <li>{@link #encryptOnce(DBESDKTestServerClient, String, Map)},
 *       {@link #copy(Map)}, {@link #bytesOf(AttributeValue)} — the tiny
 *       glue every test reuses.</li>
 *   <li>{@link #resolveKmsKeyArn()} — the resolved KMS ARN (overridable via
 *       system property or environment variable, defaulted to the shared test
 *       key).</li>
 * </ul>
 */
final class DbeTestHelpers {

    private DbeTestHelpers() {}

    // ------------------------------------------------------------------
    // Schema constants — shared across every DB-ESDK cross-language test.
    // ------------------------------------------------------------------

    static final String HEAD = "aws_dbe_head";
    static final String FOOT = "aws_dbe_foot";
    static final String TABLE = "dbesdk-test-server-table";
    static final String PK = "PK";
    static final String SECRET = "secret";
    static final String PUBLIC = "public";

    private static final String SYMMETRIC_KEY_ARN_PROPERTY = "dbesdk.testserver.kms.symmetricKeyArn";
    private static final String SYMMETRIC_KEY_ARN_ENV = "DBESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN";
    // The ESDK-shared test key deployed by the CDK stack into the CI-resources
    // account. A KMS key ARN is a resource identifier, not a secret; access is
    // still gated by AWS credentials.
    private static final String DEFAULT_SYMMETRIC_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/d3c7fc4c-5e03-4186-9d8e-ac95a6dc2f34";

    // ------------------------------------------------------------------
    // Pair provider — the single point every test class binds @MethodSource
    // to. Reads the shared, singleton registry populated by the orchestrator
    // via the -Dtestserver.targets system property.
    // ------------------------------------------------------------------

    /**
     * @return every launched {@code (encrypt, decrypt)} pair, in configuration
     *     order. With a single configured target this is one self-pair; with
     *     N targets it is the full N² matrix. Same list instance for the
     *     whole JVM run.
     */
    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    // ------------------------------------------------------------------
    // Schema + plaintext.
    // ------------------------------------------------------------------

    /**
     * @return the standard action map: {@code PK}=SIGN_ONLY,
     *     {@code secret}=ENCRYPT_AND_SIGN, {@code public}=SIGN_ONLY.
     */
    static Map<String, CryptoAction> standardActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        return actions;
    }

    /**
     * @return the shared 3-attribute plaintext. Deterministic so tests can
     *     assert plaintext equality on round-trip.
     */
    static Map<String, AttributeValue> canonicalPlaintext() {
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("item-1").build());
        plaintext.put(SECRET, AttributeValue.builder().s("hunter2").build());
        plaintext.put(PUBLIC, AttributeValue.builder().s("hello world").build());
        return plaintext;
    }

    // ------------------------------------------------------------------
    // KMS-backed client + encrypt helper.
    // ------------------------------------------------------------------

    /**
     * Build a DBE client on {@code client} using an AWS-KMS keyring pinned to
     * {@link #resolveKmsKeyArn()}. Both sides of a cross-language pair build
     * against the same key, so a wire EDK unwraps identically on either end.
     *
     * @param unsignedAttributes explicit unsigned-attribute names (empty for
     *     the default schema); the prefix rule is always {@code ":"}.
     * @return the {@code clientId} the server assigned to this configuration.
     */
    static String newKmsClient(
            DBESDKTestServerClient client,
            String tableName,
            String partitionKeyName,
            Map<String, CryptoAction> actions,
            List<String> unsignedAttributes) {
        DBEClientConfig.Builder builder = DBEClientConfig.builder()
            .logicalTableName(tableName)
            .partitionKeyName(partitionKeyName)
            .attributeActionsOnEncrypt(actions)
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build());
        if (!unsignedAttributes.isEmpty()) {
            builder.allowedUnsignedAttributes(unsignedAttributes);
        }
        CreateClientOutput created = client.createClient(
            CreateClientInput.builder().config(builder.build()).build());
        return created.getClientId();
    }

    /**
     * EncryptItem on {@code client} for {@code cid} with {@code plaintext} and
     * return the encrypted item as a mutable {@link LinkedHashMap} (so callers
     * can mutate individual attributes without disturbing the DBE library's
     * returned map).
     */
    static Map<String, AttributeValue> encryptOnce(
            DBESDKTestServerClient client, String cid, Map<String, AttributeValue> plaintext) {
        EncryptItemOutput encrypted = client.encryptItem(EncryptItemInput.builder()
            .clientId(cid)
            .plaintextItem(plaintext)
            .build());
        return new LinkedHashMap<>(encrypted.getEncryptedItem());
    }

    // ------------------------------------------------------------------
    // AttributeValue plumbing.
    // ------------------------------------------------------------------

    /** @return a mutable copy of {@code item}, preserving iteration order. */
    static Map<String, AttributeValue> copy(Map<String, AttributeValue> item) {
        return new LinkedHashMap<>(item);
    }

    /**
     * @return the bytes of {@code value.getB()}. Fails the current test when
     *     {@code value} is not a binary attribute.
     */
    static byte[] bytesOf(AttributeValue value) {
        ByteBuffer buf = value.getB();
        if (buf == null) {
            fail("expected binary AttributeValue, got " + value);
        }
        byte[] out = new byte[buf.remaining()];
        buf.duplicate().get(out);
        return out;
    }

    // ------------------------------------------------------------------
    // KMS ARN resolution.
    // ------------------------------------------------------------------

    /**
     * Resolve the AWS-KMS symmetric key ARN the tests encrypt/decrypt against.
     * Precedence: system property → environment variable → the shared default.
     */
    static String resolveKmsKeyArn() {
        String property = System.getProperty(SYMMETRIC_KEY_ARN_PROPERTY);
        if (property != null && !property.isBlank()) return property.trim();
        String env = System.getenv(SYMMETRIC_KEY_ARN_ENV);
        if (env != null && !env.isBlank()) return env.trim();
        return DEFAULT_SYMMETRIC_KEY_ARN;
    }
}
