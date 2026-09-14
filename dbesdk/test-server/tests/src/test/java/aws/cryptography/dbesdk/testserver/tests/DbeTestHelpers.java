package aws.cryptography.dbesdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientOutput;
import aws.cryptography.dbesdk.testserver.client.model.CreateTransformsClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBEAlgorithmSuiteId;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureDeclarations;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * General test helpers shared by every DB-ESDK cross-language test class
 * ({@link ItemIntegrityRejectionTests}, {@link ItemEncryptionInteropRoundTripTests}, and future additions).
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
 *   <li>{@link #standardActions()} — the SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT /
 *       ENCRYPT_AND_SIGN / SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT action map
 *       used across the suite (v2 configuration).</li>
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
public final class DbeTestHelpers {

    private DbeTestHelpers() {}

    // ------------------------------------------------------------------
    // Schema constants — shared across every DB-ESDK cross-language test.
    // ------------------------------------------------------------------

    public static final String HEAD = "aws_dbe_head";
    public static final String FOOT = "aws_dbe_foot";
    public static final String TABLE = "dbesdk-test-server-table";
    public static final String PK = "PK";
    public static final String SECRET = "secret";
    public static final String PUBLIC = "public";

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
    /**
     * The default pair source for tests that are NOT feature-gated: every
     * launched pair whose BOTH endpoints support the {@link #BASELINE_FEATURES}
     * — i.e. general-purpose DBE servers. A specialized server (e.g. a
     * legacy-only endpoint declaring the baseline keyring families unsupported)
     * is excluded here, so the ungated suite never dispatches an operation it
     * cannot serve; such a server joins only its own feature-gated tests, which
     * source {@link #allPairs()} and filter via {@link FeatureGate}. In an
     * unconfigured run (no Feature_Declarations, e.g. an offline single-server
     * smoke check) no capability is known, so filtering degrades to all pairs.
     */
    public static List<TargetPair> pairs() {
        List<TargetPair> all = LanguageServerRegistry.shared().pairs();
        FeatureDeclarations declarations = FeatureDeclarations.shared();
        if (!declarations.isConfigured()) {
            return all;
        }
        List<TargetPair> baseline = new ArrayList<>();
        for (TargetPair pair : all) {
            if (supportsBaseline(declarations, pair.encryptTarget().language())
                    && supportsBaseline(declarations, pair.decryptTarget().language())) {
                baseline.add(pair);
            }
        }
        return baseline;
    }

    /**
     * Every launched (encrypt, decrypt) pair, unfiltered — the source for
     * feature-gated tests, which call {@link FeatureGate#require} to skip the
     * pairs whose endpoints do not support the Feature under test. A
     * specialized (non-baseline) server appears only here.
     */
    public static List<TargetPair> allPairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    /**
     * The distinct configured targets, for target-local tests whose asserted
     * behavior is produced by a single server (header/legend wire encoding,
     * CreateClient validation) and therefore MUST run once per target rather than
     * across the N² pair matrix. Derived from the baseline-filtered {@link #pairs()}
     * so its target set matches that source without duplicating each target once
     * per unused decrypt endpoint.
     */
    public static List<LanguageServerTarget> targets() {
        List<LanguageServerTarget> distinct = new ArrayList<>();
        for (TargetPair pair : pairs()) {
            LanguageServerTarget target = pair.encryptTarget();
            if (!distinct.contains(target)) {
                distinct.add(target);
            }
        }
        return distinct;
    }

    /**
     * The capabilities that mark a general-purpose DBE server: the core keyring
     * families every full server supports. A pair is in the ungated
     * {@link #pairs()} suite only when both endpoints support all of these.
     */
    private static final Set<String> BASELINE_FEATURES = Set.of("aws-kms", "raw-aes");

    private static boolean supportsBaseline(FeatureDeclarations declarations, String language) {
        for (String feature : BASELINE_FEATURES) {
            if (!declarations.isSupported(language, feature)) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Schema + plaintext.
    // ------------------------------------------------------------------

    /**
     * @return the standard action map (v2 configuration): {@code PK} and
     *     {@code public}={@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT},
     *     {@code secret}={@code ENCRYPT_AND_SIGN}. Any attribute using
     *     {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} implies v2, which
     *     requires the partition (and sort, if present) key to use the same
     *     action, and causes the DBE library to emit
     *     {@code aws-crypto-attr.<NAME>} entries plus an
     *     {@code aws-crypto-legend} entry into the header's Encryption Context.
     */
    public static Map<String, CryptoAction> standardActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        return actions;
    }

    /**
     * @return the v1-configuration action map: {@code PK}={@code SIGN_ONLY},
     *     {@code secret}={@code ENCRYPT_AND_SIGN}, {@code public}={@code SIGN_ONLY}.
     *     Absence of {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} triggers a v1
     *     Configuration Version; v1 requires the partition (and sort, if present)
     *     key to use {@code SIGN_ONLY}. Under v1 the header Encryption Context
     *     also carries the partition value (v2 uses names only).
     */
    public static Map<String, CryptoAction> v1StandardActions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_ONLY);
        return actions;
    }

    /**
     * @return true if {@code actions} contains at least one
     *     {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} attribute — the
     *     condition under which the DBE library emits a non-empty header
     *     Encryption Context (an {@code aws-crypto-attr.<NAME>} entry per such
     *     attribute plus the {@code aws-crypto-legend} entry).
     */
    public static boolean hasContextAttribute(Map<String, CryptoAction> actions) {
        return actions.containsValue(CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
    }

    /**
     * @return the shared 3-attribute plaintext. Deterministic so tests can
     *     assert plaintext equality on round-trip.
     */
    public static Map<String, AttributeValue> canonicalPlaintext() {
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
    public static String newKmsClient(
            DBESDKTestServerClient client,
            String tableName,
            String partitionKeyName,
            Map<String, CryptoAction> actions,
            List<String> unsignedAttributes) {
        return newKmsClientWithSuite(
            client, tableName, partitionKeyName, actions, unsignedAttributes, null);
    }

    /**
     * Like {@link #newKmsClient} but pins an explicit algorithm suite. A
     * {@code null} suite leaves the DBE default — an ECDSA-signed suite, so the
     * header flavor is {@code 0x01} and the footer carries an ECDSA signature
     * after the Recipient Tags. The SYMSIG suite
     * ({@code ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384}) selects
     * symmetric signing → header flavor {@code 0x00} and a footer that is
     * Recipient Tags only (no signature).
     */
    public static String newKmsClientWithSuite(
            DBESDKTestServerClient client,
            String tableName,
            String partitionKeyName,
            Map<String, CryptoAction> actions,
            List<String> unsignedAttributes,
            DBEAlgorithmSuiteId algorithmSuiteId) {
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
        if (algorithmSuiteId != null) {
            builder.algorithmSuiteId(algorithmSuiteId);
        }
        CreateClientOutput created = client.createClient(
            CreateClientInput.builder().config(builder.build()).build());
        return created.getClientId();
    }

    /**
     * Like {@link #newKmsClient} but declares a sort key ({@code sortKeyName})
     * alongside the partition key. Used by the sort-key action-rule validation
     * tests: the sort attribute's action MUST be {@code SIGN_ONLY} under a v1
     * schema and {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} under a v2
     * schema, mirroring the partition-key rule.
     */
    public static String newKmsClientWithSortKey(
            DBESDKTestServerClient client,
            String tableName,
            String partitionKeyName,
            String sortKeyName,
            Map<String, CryptoAction> actions,
            List<String> unsignedAttributes) {
        DBEClientConfig.Builder builder = DBEClientConfig.builder()
            .logicalTableName(tableName)
            .partitionKeyName(partitionKeyName)
            .sortKeyName(sortKeyName)
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
     * Build a DDB-SDK transforms client on {@code client} bound to
     * {@code tableName}, over the shared AWS-KMS key with the standard (v2)
     * action map. Both sides of a cross-language pair build against the same
     * key and table config, so an item one side's write transform encrypts,
     * the other side's read transform decrypts.
     */
    public static String newTransformsClient(DBESDKTestServerClient client, String tableName) {
        return client.createTransformsClient(
            CreateTransformsClientInput.builder()
                .config(transformsConfig(tableName, null))
                .tableName(tableName)
                .build())
            .getClientId();
    }

    /**
     * Build a DDB-SDK transforms client on {@code client} bound to
     * {@code tableName} with an explicit {@code actions} map (over the shared
     * AWS-KMS key), instead of the standard 3-attribute schema. Used by tests
     * that need a non-standard attribute in the crypto schema — e.g. an
     * attribute whose NAME exercises the AttributeName byte-length boundary.
     */
    public static String newTransformsClientWithActions(
            DBESDKTestServerClient client,
            String tableName,
            Map<String, CryptoAction> actions) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(tableName)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(actions)
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .build();
        return client.createTransformsClient(
            CreateTransformsClientInput.builder().config(config).tableName(tableName).build())
            .getClientId();
    }

    /**
     * @return a single {@code M} AttributeValue nested {@code depth} levels
     *     deep: {@code depth} maps each holding one member {@code "n"}, with a
     *     terminal string {@code "leaf"} at the bottom. Used to exercise the
     *     {@code MAX_STRUCTURE_DEPTH} accept/reject boundary of the item
     *     serializer.
     */
    public static AttributeValue deeplyNestedMap(int depth) {
        AttributeValue value = AttributeValue.builder().s("leaf").build();
        for (int i = 0; i < depth; i++) {
            Map<String, AttributeValue> level = new LinkedHashMap<>();
            level.put("n", value);
            value = AttributeValue.builder().m(level).build();
        }
        return value;
    }

    /**
     * Build the transforms-client {@link DBEClientConfig} used across the DDB
     * SDK transform tests: the standard (v2) action map over the shared AWS-KMS
     * key, bound to {@code logicalTableName}. When {@code algorithmSuiteId} is
     * non-null it is set on the config, so a multi-table transforms client can
     * give each table its own suite.
     */
    public static DBEClientConfig transformsConfig(
            String logicalTableName, DBEAlgorithmSuiteId algorithmSuiteId) {
        DBEClientConfig.Builder builder = DBEClientConfig.builder()
            .logicalTableName(logicalTableName)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build());
        if (algorithmSuiteId != null) {
            builder.algorithmSuiteId(algorithmSuiteId);
        }
        return builder.build();
    }

    /**
     * Like {@link #transformsConfig} but declares a composite key: partition
     * key {@link #PK} plus {@code sortKeyName}. The sort attribute is added to
     * the standard (v2) action map as
     * {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT} (the v2 sort-key rule, the
     * same action the partition key uses), so its value is signed and preserved
     * verbatim on the wire. A transforms client built from this config matches
     * an unprocessed item back to the original request by the full
     * (partition + sort) key rather than the partition key alone.
     */
    public static DBEClientConfig transformsConfigWithSortKey(
            String logicalTableName, String sortKeyName) {
        Map<String, CryptoAction> actions = standardActions();
        actions.put(sortKeyName, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        return DBEClientConfig.builder()
            .logicalTableName(logicalTableName)
            .partitionKeyName(PK)
            .sortKeyName(sortKeyName)
            .attributeActionsOnEncrypt(actions)
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .build();
    }

    /**
     * EncryptItem on {@code client} for {@code cid} with {@code plaintext} and
     * return the encrypted item as a mutable {@link LinkedHashMap} (so callers
     * can mutate individual attributes without disturbing the DBE library's
     * returned map).
     */
    public static Map<String, AttributeValue> encryptOnce(
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
    public static Map<String, AttributeValue> copy(Map<String, AttributeValue> item) {
        return new LinkedHashMap<>(item);
    }

    /**
     * @return the bytes of {@code value.getB()}. Fails the current test when
     *     {@code value} is not a binary attribute.
     */
    public static byte[] bytesOf(AttributeValue value) {
        ByteBuffer buf = value.getB();
        if (buf == null) {
            fail("expected binary AttributeValue, got " + value);
        }
        byte[] out = new byte[buf.remaining()];
        buf.duplicate().get(out);
        return out;
    }

    // ------------------------------------------------------------------
    // Header wire-format helpers — Encrypt Legend + assertions.
    // ------------------------------------------------------------------

    /**
     * @return the header's Encrypt Legend Length. The Encrypt Legend is a
     *     UInt16 big-endian length at header bytes 34-35, followed by that many
     *     bytes starting at 36 — one byte per authenticated attribute per
     *     {@code specification/structured-encryption/header.md#encrypt-legend}.
     */
    public static int encryptLegendLength(Map<String, AttributeValue> item) {
        byte[] header = bytesOf(item.get(HEAD));
        return ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
    }

    /**
     * @return the header's Encrypt Legend bytes. Each byte encodes the Crypto
     *     Action of one authenticated attribute: {@code 0x65 'e'} for
     *     {@code ENCRYPT_AND_SIGN}, {@code 0x73 's'} for {@code SIGN_ONLY},
     *     {@code 0x63 'c'} for {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}.
     *     Attributes appear in canonical (lexicographic-by-path) order.
     */
    public static byte[] encryptLegendBytes(Map<String, AttributeValue> item) {
        byte[] header = bytesOf(item.get(HEAD));
        int len = ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
        byte[] out = new byte[len];
        System.arraycopy(header, 36, out, 0, len);
        return out;
    }

    /**
     * Parse the header's Encryption Context section into a map of UTF-8 keys →
     * UTF-8 values. Layout per
     * {@code specification/structured-encryption/header.md#encryption-context}:
     * <pre>
     *   bytes 34-35       UInt16 BE — Encrypt Legend Length
     *   bytes 36..        Encrypt Legend bytes
     *   next 2 bytes      UInt16 BE — EC entry count
     *   for each entry:   UInt16 BE key length, key bytes, UInt16 BE value length, value bytes
     * </pre>
     */
    public static Map<String, String> parseHeaderEncryptionContext(byte[] header) {
        int legendLen = ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
        int off = 36 + legendLen;
        int ecCount = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
        off += 2;
        Map<String, String> ec = new LinkedHashMap<>();
        for (int i = 0; i < ecCount; i++) {
            int keyLen = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
            off += 2;
            String key = new String(header, off, keyLen, java.nio.charset.StandardCharsets.UTF_8);
            off += keyLen;
            int valLen = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
            off += 2;
            String val = new String(header, off, valLen, java.nio.charset.StandardCharsets.UTF_8);
            off += valLen;
            ec.put(key, val);
        }
        return ec;
    }

    /**
     * The Encrypted Data Key count from a serialized {@code aws_dbe_head}: walk
     * past the Encrypt Legend and the Encryption Context to the 2-byte EDK count
     * that precedes the EDK entries. Lets a test derive the footer's
     * Recipient-Tag length (48 bytes per EDK) from the wire rather than a
     * hard-coded key count.
     */
    public static int parseHeaderEdkCount(byte[] header) {
        int legendLen = ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
        int off = 36 + legendLen;
        int ecCount = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
        off += 2;
        for (int i = 0; i < ecCount; i++) {
            int keyLen = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
            off += 2 + keyLen;
            int valLen = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
            off += 2 + valLen;
        }
        // Encrypted Data Key Count is a single unsigned 8-bit byte (header.md).
        return header[off] & 0xFF;
    }

    /**
     * Assert every attribute in {@link #canonicalPlaintext()} round-trips
     * through {@code decrypted}. {@code label} identifies the direction under
     * test in the failure message ({@code v1}, {@code v2}, {@code v1→v2},
     * {@code v2→v1}).
     */
    public static void assertPlaintextPreserved(
            String label, DecryptItemOutput decrypted, TargetPair pair) {
        assertPlaintextPreserved(label, canonicalPlaintext(), decrypted, pair);
    }

    /**
     * Assert every attribute in {@code expected} appears with the same string
     * value in {@code decrypted}. {@code label} identifies the direction under
     * test in the failure message.
     */
    public static void assertPlaintextPreserved(
            String label,
            Map<String, AttributeValue> expected,
            DecryptItemOutput decrypted,
            TargetPair pair) {
        for (Map.Entry<String, AttributeValue> entry : expected.entrySet()) {
            AttributeValue actual = decrypted.getPlaintextItem().get(entry.getKey());
            assertNotNull(actual,
                label + " round-trip lost attribute '" + entry.getKey() + "' on " + pair);
            assertEquals(entry.getValue().getS(), actual.getS(),
                label + " round-trip must preserve attribute '" + entry.getKey() + "' on " + pair);
        }
    }

    // ------------------------------------------------------------------
    // Deep AttributeValue equality — shared across the interop suites.
    // Sets (SS/NS/BS) compare order-independently; lists (L) preserve order;
    // maps (M) compare by key. Recurses for L and M.
    // ------------------------------------------------------------------

    /**
     * Assert {@code actual} deep-equals {@code expected} as a DDB
     * {@link AttributeValue}. Sets ({@code SS}/{@code NS}/{@code BS}) are
     * compared as unordered sets (DBE canonicalizes Set element order, and
     * DynamoDB itself does not preserve it); lists ({@code L}) preserve order;
     * maps ({@code M}) compare by key and recurse. {@code label} and
     * {@code pair} identify the failing attribute in the message.
     */
    public static void assertAttributeEquals(
            AttributeValue expected, AttributeValue actual, String label, TargetPair pair) {
        assertNotNull(actual, label + " round-trip lost the attribute on " + pair);
        String ctx = label + " on " + pair;
        if (expected.getS() != null) {
            assertEquals(expected.getS(), actual.getS(), ctx);
        } else if (expected.getN() != null) {
            assertEquals(expected.getN(), actual.getN(), ctx);
        } else if (expected.isBool() != null) {
            assertEquals(expected.isBool(), actual.isBool(), ctx);
        } else if (expected.isNull() != null) {
            assertEquals(expected.isNull(), actual.isNull(), ctx);
        } else if (expected.hasSs()) {
            assertEquals(new HashSet<>(expected.getSs()), new HashSet<>(actual.getSs()), ctx);
        } else if (expected.hasNs()) {
            assertEquals(new HashSet<>(expected.getNs()), new HashSet<>(actual.getNs()), ctx);
        } else if (expected.hasBs()) {
            assertEquals(byteSet(expected.getBs()), byteSet(actual.getBs()), ctx);
        } else if (expected.hasL()) {
            List<AttributeValue> exp = expected.getL();
            List<AttributeValue> act = actual.getL();
            assertEquals(exp.size(), act.size(), ctx + " list size");
            for (int i = 0; i < exp.size(); i++) {
                assertAttributeEquals(exp.get(i), act.get(i), label + "[" + i + "]", pair);
            }
        } else if (expected.hasM()) {
            Map<String, AttributeValue> exp = expected.getM();
            Map<String, AttributeValue> act = actual.getM();
            assertEquals(exp.keySet(), act.keySet(), ctx + " map keys");
            for (Map.Entry<String, AttributeValue> e : exp.entrySet()) {
                assertAttributeEquals(e.getValue(), act.get(e.getKey()), label + "." + e.getKey(), pair);
            }
        } else {
            assertEquals(expected.toString(), actual.toString(), ctx + " (unhandled variant)");
        }
    }

    /** Normalize a binary set to a content-comparable, order-independent set. */
    public static Set<List<Byte>> byteSet(List<ByteBuffer> bufs) {
        Set<List<Byte>> out = new HashSet<>();
        for (ByteBuffer buf : bufs) {
            ByteBuffer dup = buf.duplicate();
            List<Byte> bytes = new ArrayList<>(dup.remaining());
            while (dup.hasRemaining()) {
                bytes.add(dup.get());
            }
            out.add(bytes);
        }
        return out;
    }

    // ------------------------------------------------------------------
    // KMS ARN resolution.
    // ------------------------------------------------------------------

    /**
     * Resolve the AWS-KMS symmetric key ARN the tests encrypt/decrypt against.
     * Precedence: system property → environment variable → the shared default.
     */
    public static String resolveKmsKeyArn() {
        String property = System.getProperty(SYMMETRIC_KEY_ARN_PROPERTY);
        if (property != null && !property.isBlank()) return property.trim();
        String env = System.getenv(SYMMETRIC_KEY_ARN_ENV);
        if (env != null && !env.isBlank()) return env.trim();
        return DEFAULT_SYMMETRIC_KEY_ARN;
    }
}
