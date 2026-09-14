package aws.cryptography.dbesdk.testserver.tests.compatibility;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.v1StandardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.LegacyOverride;
import aws.cryptography.dbesdk.testserver.client.model.LegacyPolicy;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for legacy-DDBEC interop — the modern DBE
 * item encryptor reading (and, under a FORCE_LEGACY policy, writing) items in
 * the format of the legacy DynamoDB Encryption Client via a LegacyOverride.
 *
 * <p>Legacy interop is NOT uniformly available. The modern DBE LegacyOverride
 * delegates to a legacy DynamoDBEncryptor, which only the Java DBE library
 * bundles; the Rust and .NET libraries have no equivalent. This is modeled by
 * the {@code legacy-ddbec} Feature — declared <em>supported</em> only for the
 * Java Language_Server. Every test calls {@link FeatureGate#require} first, so
 * only the Java→Java pair runs and every pair involving Rust or .NET is visibly
 * skipped.
 *
 * <p>Three bounded properties:
 * <ul>
 *   <li>A FORCE_LEGACY client writes a genuine legacy-format item (carrying the
 *       {@code *amzn-ddb-map-sig*}/{@code *amzn-ddb-map-desc*} attributes and no
 *       modern {@code aws_dbe_head}) that round-trips on decrypt.</li>
 *   <li>A FORBID_LEGACY_DECRYPT client rejects a legacy-format item.</li>
 *   <li>A migration client (FORBID_LEGACY_ENCRYPT, ALLOW_LEGACY_DECRYPT) reads
 *       a legacy-format item back to its plaintext — the read side of a
 *       legacy→modern migration.</li>
 * </ul>
 *
 * <p>Legacy is Java-only: there is no Python target and no checked-in legacy
 * vector. The legacy item each test reads is produced by a FORCE_LEGACY client
 * on the same Java server, so these prove the modern Java wrapper's legacy
 * read/write <em>policy</em> — the scope of this coverage — rather than
 * interoperability with an independently produced legacy record.
 */
class LegacyDdbecCompatibilityTests {

    private static final String TABLE = "dbesdk-test-server-table";
    private static final String LEGACY_SIGNATURE = "*amzn-ddb-map-sig*";
    private static final String LEGACY_DESCRIPTION = "*amzn-ddb-map-desc*";
    private static final String MODERN_HEADER = "aws_dbe_head";

    /**
     * A modern client config carrying a legacy override on the shared KMS key,
     * in the v1 action configuration (the legacy encryptor cannot encrypt the
     * partition key, so PK is SIGN_ONLY).
     */
    private static DBEClientConfig legacyConfig(LegacyPolicy policy) {
        return DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(v1StandardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .legacyOverride(LegacyOverride.builder()
                .policy(policy)
                .kmsKeyId(resolveKmsKeyArn())
                .attributeActionsOnEncrypt(v1StandardActions())
                .build())
            .build();
    }

    /**
     * A modern Java DB-ESDK client (ALLOW_LEGACY_DECRYPT) reads a genuine legacy
     * record that was produced INDEPENDENTLY — by the old
     * {@code DynamoDBEncryptor.encryptRecord} API directly, offline, and checked
     * in as a frozen vector ({@code resources/legacy-vectors/java-legacy-item.txt};
     * see the vector producer under {@code /tmp/legacy-proto}). Unlike a
     * FORCE_LEGACY write-then-read in the same wrapper, this proves the modern
     * client can decrypt data written by the genuinely-old library.
     *
     * <p>The vector is KMS-encrypted under the shared key and its EncryptionContext
     * (table {@code dbesdk-test-server-table}, hash key {@code PK}) + flags
     * (PK/public SIGN, secret ENCRYPT+SIGN) match what the LegacyOverride
     * reconstructs from {@code logicalTableName}/{@code partitionKeyName} +
     * {@code v1StandardActions()}, so any target with a valid legacy adapter can
     * decrypt it — gated to Java (the only target with the adapter).
     */
    @ParameterizedTest(name = "[legacy] modern client reads an independently produced Java legacy vector {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#allPairs")
    void modernClientReadsIndependentJavaLegacyVector(TargetPair pair) {
        FeatureGate.require(Set.of("legacy-ddbec"), pair);
        Map<String, AttributeValue> legacyVector = loadLegacyVector();
        DBESDKTestServerClient decryptClient = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String decryptId = decryptClient.createClient(CreateClientInput.builder()
            .config(legacyConfig(LegacyPolicy.FORBID_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT)).build())
            .getClientId();
        Map<String, AttributeValue> recovered = decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptId).encryptedItem(legacyVector).build())
            .getPlaintextItem();
        assertEquals("classified-value", recovered.get(SECRET).getS(),
            "modern client must recover the encrypted 'secret' from the independent legacy vector");
        assertEquals("plain-value", recovered.get(PUBLIC).getS(),
            "modern client must recover the signed 'public' from the independent legacy vector");
        assertEquals("partition-1", recovered.get(PK).getS(),
            "modern client must recover the partition key from the independent legacy vector");
    }

    /**
     * Load the checked-in legacy vector: one {@code name|type|value} line per
     * attribute, type {@code S} (raw string) or {@code B} (base64-encoded bytes).
     */
    private static Map<String, AttributeValue> loadLegacyVector() {
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        try (InputStream in =
                 LegacyDdbecCompatibilityTests.class.getResourceAsStream("/legacy-vectors/java-legacy-item.txt");
             BufferedReader reader =
                 new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                int firstBar = line.indexOf('|');
                int secondBar = line.indexOf('|', firstBar + 1);
                String name = line.substring(0, firstBar);
                String type = line.substring(firstBar + 1, secondBar);
                String value = line.substring(secondBar + 1);
                if ("S".equals(type)) {
                    item.put(name, AttributeValue.builder().s(value).build());
                } else if ("B".equals(type)) {
                    item.put(name, AttributeValue.builder()
                        .b(ByteBuffer.wrap(Base64.getDecoder().decode(value))).build());
                } else {
                    throw new IllegalStateException("unknown vector attribute type: " + type);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("failed to load the legacy vector resource", e);
        }
        return item;
    }

    @ParameterizedTest(name = "[legacy] force-legacy round-trip {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#allPairs")
    void forceLegacyEncryptRoundTrips(TargetPair pair) {
        FeatureGate.require(Set.of("legacy-ddbec"), pair);
        DBEClientConfig config = legacyConfig(LegacyPolicy.FORCE_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT);
        DBESDKTestServerClient encryptClient = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        String encryptId = encryptClient.createClient(
            CreateClientInput.builder().config(config).build()).getClientId();
        Map<String, AttributeValue> encrypted = encryptClient.encryptItem(
            EncryptItemInput.builder().clientId(encryptId).plaintextItem(canonicalPlaintext()).build())
            .getEncryptedItem();

        assertTrue(encrypted.containsKey(LEGACY_SIGNATURE) && encrypted.containsKey(LEGACY_DESCRIPTION),
            "force-legacy item must carry the legacy signature/description attributes");
        assertFalse(encrypted.containsKey(MODERN_HEADER),
            "force-legacy item must not carry the modern aws_dbe_head");

        String decryptId = decryptClient.createClient(
            CreateClientInput.builder().config(config).build()).getClientId();
        Map<String, AttributeValue> recovered = decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptId).encryptedItem(encrypted).build())
            .getPlaintextItem();

        assertEquals("hunter2", recovered.get(SECRET).getS(), "encrypted 'secret' must round-trip");
        assertEquals("item-1", recovered.get(PK).getS());
        assertEquals("hello world", recovered.get(PUBLIC).getS());
    }

    @ParameterizedTest(name = "[legacy] forbid-legacy-decrypt rejects a legacy item {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#allPairs")
    void forbidLegacyDecryptRejectsLegacyItem(TargetPair pair) {
        FeatureGate.require(Set.of("legacy-ddbec"), pair);
        DBESDKTestServerClient encryptClient = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        String encryptId = encryptClient.createClient(CreateClientInput.builder()
            .config(legacyConfig(LegacyPolicy.FORCE_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT)).build())
            .getClientId();
        Map<String, AttributeValue> legacyItem = encryptClient.encryptItem(
            EncryptItemInput.builder().clientId(encryptId).plaintextItem(canonicalPlaintext()).build())
            .getEncryptedItem();

        String decryptId = decryptClient.createClient(CreateClientInput.builder()
            .config(legacyConfig(LegacyPolicy.FORBID_LEGACY_ENCRYPT_FORBID_LEGACY_DECRYPT)).build())
            .getClientId();
        assertThrows(DBESDKClientError.class, () -> decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptId).encryptedItem(legacyItem).build()),
            "a forbid-legacy-decrypt client must reject a legacy-format item");
    }

    @ParameterizedTest(name = "[legacy] migration client (forbid-encrypt/allow-decrypt) reads a legacy item {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#allPairs")
    void forbidLegacyEncryptAllowLegacyDecryptReadsLegacyItem(TargetPair pair) {
        FeatureGate.require(Set.of("legacy-ddbec"), pair);
        DBESDKTestServerClient encryptClient = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());

        // A legacy-format item, produced by a FORCE_LEGACY client on the Java
        // server (legacy is Java-only, so the encrypt endpoint is the Java server).
        String encryptId = encryptClient.createClient(CreateClientInput.builder()
            .config(legacyConfig(LegacyPolicy.FORCE_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT)).build())
            .getClientId();
        Map<String, AttributeValue> legacyItem = encryptClient.encryptItem(
            EncryptItemInput.builder().clientId(encryptId).plaintextItem(canonicalPlaintext()).build())
            .getEncryptedItem();

        // The migration policy — write modern, still read legacy — decrypts it.
        String decryptId = decryptClient.createClient(CreateClientInput.builder()
            .config(legacyConfig(LegacyPolicy.FORBID_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT)).build())
            .getClientId();
        Map<String, AttributeValue> recovered = decryptClient.decryptItem(
            DecryptItemInput.builder().clientId(decryptId).encryptedItem(legacyItem).build())
            .getPlaintextItem();

        assertEquals("hunter2", recovered.get(SECRET).getS(),
            "a forbid-encrypt/allow-decrypt client must still read a legacy item");
        assertEquals("item-1", recovered.get(PK).getS());
        assertEquals("hello world", recovered.get(PUBLIC).getS());
    }
}
