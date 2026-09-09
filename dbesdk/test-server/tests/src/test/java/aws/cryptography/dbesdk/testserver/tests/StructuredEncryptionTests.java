package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AuthenticateAction;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateStructuredClientInput;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DecryptStructureInput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptStructureInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.StructuredDataTerminal;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Structured Encryption (§0.3.5) — the raw structured layer beneath the item
 * encryptor. Cohesive property: a flat structured-data map (field name →
 * terminal of opaque value bytes + a 2-byte type id) encrypted under a Crypto
 * Schema round-trips through {@code DecryptStructure}, and the
 * {@code ENCRYPT_AND_SIGN} terminal is genuinely encrypted (its bytes change and
 * the header/footer terminals are added).
 *
 * <p>The DBE {@code StructuredEncryption} client is public only in Java and .NET
 * (Rust exposes it as {@code pub(crate)}), so this exercises the
 * {@code structured-encryption} feature, which Rust declares unsupported. Every
 * test calls {@link FeatureGate#require} first, so the pairs involving a Rust
 * endpoint are skipped and the Java↔.NET pairs run.
 */
class StructuredEncryptionTests {

    private static final String FEATURE = "structured-encryption";
    private static final String SECRET = "secret";
    private static final String PUBLIC = "public";
    private static final byte[] TYPE_ID = {0x00, 0x02}; // arbitrary 2-byte type id (STRING)

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    @ParameterizedTest(name = "[structured] structure round-trip preserves terminals {0}")
    @MethodSource("testPairs")
    void structureRoundTripPreservesTerminals(TargetPair pair) {
        FeatureGate.require(Set.of(FEATURE), pair);
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, StructuredDataTerminal> plaintext = plaintextStructure();

        Map<String, StructuredDataTerminal> encrypted = encryptClient.encryptStructure(
            EncryptStructureInput.builder()
                .clientId(newStructuredClient(encryptClient))
                .tableName(TABLE)
                .plaintextStructure(plaintext)
                .cryptoSchema(cryptoSchema())
                .build()).getEncryptedStructure();

        Map<String, StructuredDataTerminal> recovered = decryptClient.decryptStructure(
            DecryptStructureInput.builder()
                .clientId(newStructuredClient(decryptClient))
                .tableName(TABLE)
                .encryptedStructure(encrypted)
                .authenticateSchema(authenticateSchema(encrypted))
                .build()).getPlaintextStructure();

        for (String field : plaintext.keySet()) {
            assertNotNull(recovered.get(field),
                "recovered structure missing '" + field + "' on " + pair);
            assertArrayEquals(bytes(plaintext.get(field)), bytes(recovered.get(field)),
                "terminal '" + field + "' did not round-trip on " + pair);
        }
    }

    @ParameterizedTest(name = "[structured] EncryptStructure encrypts the ENCRYPT_AND_SIGN terminal {0}")
    @MethodSource("testPairs")
    void encryptStructureEncryptsTheEncryptAndSignTerminal(TargetPair pair) {
        FeatureGate.require(Set.of(FEATURE), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        Map<String, StructuredDataTerminal> plaintext = plaintextStructure();

        Map<String, StructuredDataTerminal> encrypted = client.encryptStructure(
            EncryptStructureInput.builder()
                .clientId(newStructuredClient(client))
                .tableName(TABLE)
                .plaintextStructure(plaintext)
                .cryptoSchema(cryptoSchema())
                .build()).getEncryptedStructure();

        assertTrue(encrypted.size() > plaintext.size(),
            "EncryptStructure must add header/footer terminals on " + pair);
        assertFalse(java.util.Arrays.equals(bytes(plaintext.get(SECRET)), bytes(encrypted.get(SECRET))),
            "the ENCRYPT_AND_SIGN terminal's bytes must be encrypted on " + pair);
    }

    /** A structured client over an AWS-KMS keyring on the shared item key. */
    private static String newStructuredClient(DBESDKTestServerClient client) {
        DBEClientConfig config = DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(DbeTestHelpers.standardActions())
            .allowedUnsignedAttributePrefix(":")
            .keyring(Keyring.builder()
                .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
                .build())
            .build();
        return client.createStructuredClient(
            CreateStructuredClientInput.builder().config(config).build()).getClientId();
    }

    /** PK (signed + in context), a secret (encrypted), and a public (signed) terminal. */
    private static Map<String, StructuredDataTerminal> plaintextStructure() {
        Map<String, StructuredDataTerminal> structure = new LinkedHashMap<>();
        structure.put(PK, terminal("item-1"));
        structure.put(SECRET, terminal("hunter2"));
        structure.put(PUBLIC, terminal("visible"));
        return structure;
    }

    private static Map<String, CryptoAction> cryptoSchema() {
        Map<String, CryptoAction> schema = new LinkedHashMap<>();
        schema.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        schema.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        schema.put(PUBLIC, CryptoAction.SIGN_ONLY);
        return schema;
    }

    /**
     * The Authenticate Schema for decrypt: it must cover every key in the
     * encrypted structure. The source fields are within the signature scope
     * ({@code SIGN}); the DBE-added terminals ({@code aws_dbe_head} describing the
     * crypto and {@code aws_dbe_foot} holding the signature) are {@code DO_NOT_SIGN}.
     */
    private static Map<String, AuthenticateAction> authenticateSchema(
            Map<String, StructuredDataTerminal> encrypted) {
        Map<String, AuthenticateAction> schema = new LinkedHashMap<>();
        for (String key : encrypted.keySet()) {
            schema.put(key, key.startsWith("aws_dbe_")
                ? AuthenticateAction.DO_NOT_SIGN
                : AuthenticateAction.SIGN);
        }
        return schema;
    }

    private static StructuredDataTerminal terminal(String value) {
        return StructuredDataTerminal.builder()
            .value(ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8)))
            .typeId(ByteBuffer.wrap(TYPE_ID))
            .build();
    }

    private static byte[] bytes(StructuredDataTerminal terminal) {
        ByteBuffer buffer = terminal.getValue().duplicate();
        byte[] out = new byte[buffer.remaining()];
        buffer.get(out);
        return out;
    }
}
