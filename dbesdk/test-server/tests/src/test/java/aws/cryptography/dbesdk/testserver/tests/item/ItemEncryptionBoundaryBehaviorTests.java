package aws.cryptography.dbesdk.testserver.tests.item;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertPlaintextPreserved;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertAttributeEquals;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.KnownBugGate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Round-trip fidelity at item-shape boundaries. Each test builds a bespoke
 * plaintext (or schema) that stresses one edge of what the DBE library must
 * still round-trip cleanly. Distinct from
 * {@link V1EncryptionContextBehaviorTests} / {@link V2EncryptionContextBehaviorTests},
 * which use the canonical 3-attribute plaintext — this file's cohesive property
 * is "unusual item shapes", not "Configuration Version behavior".
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #largeItemRoundTripPreservesPlaintext} — item near the DDB 400 KB size limit</li>
 *   <li>{@link #emptyItemRoundTripPreservesPlaintext} — item with only the required partition key</li>
 *   <li>{@link #missingAllowedUnsignedAttributeRoundTripSucceeds} — schema declares an
 *       {@code allowedUnsignedAttributes} attribute; item omits it; encrypt/decrypt succeed</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 3 assertions × pairs²}.
 */
class ItemEncryptionBoundaryBehaviorTests {

    /**
     * Plaintext byte target for the large-item test — a single attribute value
     * whose UTF-8 size approaches DDB's 400 KB item limit but leaves room for
     * the DBE header/footer overhead so the item itself stays writable.
     */
    private static final int LARGE_VALUE_BYTES = 350_000;

    /** Allowed-unsigned attribute name used by the missing-optional test. */
    private static final String OPTIONAL_ATTR = "optional";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /**
     * A large plaintext value in an encrypted attribute must survive round-trip.
     * Uses the standard v2 schema; sets {@code secret} to a 350 KB string.
     */
    @ParameterizedTest(name = "large-item round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void largeItemRoundTripPreservesPlaintext(TargetPair pair) {
        String bigValue = "x".repeat(LARGE_VALUE_BYTES);
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("large-item-key").build());
        plaintext.put(SECRET, AttributeValue.builder().s(bigValue).build());
        plaintext.put(PUBLIC, AttributeValue.builder().s("large-item-public").build());

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, standardActions(), List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("large-item", plaintext, decrypted, pair);
    }

    /**
     * An item consisting of only the partition key (no other attributes) must
     * round-trip. Uses a minimal v2 schema declaring only PK.
     */
    @ParameterizedTest(name = "empty-item round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void emptyItemRoundTripPreservesPlaintext(TargetPair pair) {
        Map<String, CryptoAction> pkOnly = new LinkedHashMap<>();
        pkOnly.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("empty-item-key").build());

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, pkOnly, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, pkOnly, List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("empty-item", plaintext, decrypted, pair);
    }

    /**
     * A schema declaring an attribute in {@code allowedUnsignedAttributes} must
     * still round-trip an item that omits that attribute. Proves an "optional"
     * attribute is genuinely optional — the item passing through without it is
     * a valid write.
     */
    @ParameterizedTest(name = "missing allowed-unsigned attribute round-trip succeeds {0}")
    @MethodSource("testPairs")
    void missingAllowedUnsignedAttributeRoundTripSucceeds(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId =
            newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of(OPTIONAL_ATTR));
        String decryptClientId =
            newKmsClient(decryptClient, TABLE, PK, standardActions(), List.of(OPTIONAL_ATTR));
        Map<String, AttributeValue> plaintext = canonicalPlaintext(); // no OPTIONAL_ATTR
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertPlaintextPreserved("missing-optional", decrypted, pair);
    }

    /**
     * An attribute NAME containing multi-byte UTF-8 characters must round-trip
     * correctly. The DBE library measures attribute-name length by BYTE count,
     * not char count — regression coverage for
     * <a href="https://github.com/aws/aws-database-encryption-sdk-dynamodb/commit/1520838e">fix 1520838e</a>.
     * A byte-length off-by-N bug here would misplace bytes in the canonical
     * hash and silently corrupt the tag.
     */
    @ParameterizedTest(name = "UTF-8 attribute name round-trip preserves plaintext {0}")
    @MethodSource("testPairs")
    void utf8AttributeNameRoundTripPreservesPlaintext(TargetPair pair) {
        // "café" = 4 chars, 5 UTF-8 bytes (é is 2 bytes) — char vs byte length differ
        final String utf8AttrName = "caf\u00e9";
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(PUBLIC, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(utf8AttrName, CryptoAction.SIGN_ONLY);

        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("utf8-key").build());
        plaintext.put(SECRET, AttributeValue.builder().s("utf8-secret").build());
        plaintext.put(PUBLIC, AttributeValue.builder().s("utf8-public").build());
        plaintext.put(utf8AttrName, AttributeValue.builder().s("caf\u00e9-value").build());

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        //= specification/structured-encryption/header.md#canonical-path
        //= type=test
        //= reason=cross-language round-trip of a multi-byte attribute name proves the key length is measured in bytes
        //# For Structured Data in Structured Data Maps, this MUST be a 0x24 byte ($ in UTF-8),
        //# followed by the length of the key, followed by the key as a UTF8 string.
        assertPlaintextPreserved("utf8-attr-name", plaintext, decrypted, pair);
    }

    /**
     * An item with a large attribute <em>count</em> (90 encrypted attributes)
     * round-trips — the per-attribute-framing-at-scale boundary, distinct from
     * {@link #largeItemRoundTripPreservesPlaintext} (a large single value). DBE
     * caps an item at 100 attributes, so this stays under that limit.
     */
    @ParameterizedTest(name = "many-attribute item round-trip {0}")
    @MethodSource("testPairs")
    void manyAttributeItemRoundTrip(TargetPair pair) {
        final int count = 90;
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("many-attr-key").build());
        for (int i = 0; i < count; i++) {
            String name = "attr" + i;
            actions.put(name, CryptoAction.ENCRYPT_AND_SIGN);
            plaintext.put(name, AttributeValue.builder().s("v" + i).build());
        }
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encId, plaintext);
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decId).encryptedItem(item).build());
        assertPlaintextPreserved("many-attr", plaintext, decrypted, pair);
    }

    /**
     * An item nested to {@code MAX_STRUCTURE_DEPTH} (32) round-trips (Dafny
     * {@code DynamoToStruct.dfy}: {@code TestMaxDepth}). 31 nested maps is the
     * deepest structure the serializer accepts; one level over is rejected (see
     * {@code ItemEncryptionRuntimeValidationTests#encryptItemRejectsOverMaxDepth}).
     *
     * <p>java-v3 cannot carry an item this deep: smithy-java 1.4.0 overflows a
     * fixed-size validator path array on the recursive request shape (a
     * framework {@code InternalFailureException}) below the product depth
     * limit. That is the declared known bug
     * {@code java-deep-nesting-request-validation-overflow}; the gate turns a
     * java-v3 encrypt into a visible skip and fails loudly if a smithy-java
     * upgrade ever lets it through, while net-v4 and rust-v1 assert the
     * round-trip.
     */
    @ParameterizedTest(name = "max-depth nested item round-trips {0}")
    @MethodSource("testPairs")
    void maxDepthNestedItemRoundTrips(TargetPair pair) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put("value", CryptoAction.ENCRYPT_AND_SIGN);
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("max-depth-key").build());
        plaintext.put("value", DbeTestHelpers.deeplyNestedMap(31));

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        KnownBugGate.gateDeclared(
            "java-deep-nesting-request-validation-overflow",
            pair.encryptTarget().language(),
            () -> {
                Map<String, AttributeValue> item = assertDoesNotThrow(
                    () -> encryptOnce(encryptClient, encId, plaintext),
                    "encrypting an item nested to the depth limit must succeed on " + pair);
                DecryptItemOutput decrypted = assertDoesNotThrow(
                    () -> decryptClient.decryptItem(DecryptItemInput.builder()
                        .clientId(decId).encryptedItem(item).build()),
                    "decrypting a max-depth item must succeed on " + pair);
                assertAttributeEquals(plaintext.get("value"),
                    decrypted.getPlaintextItem().get("value"), "max-depth nested value", pair);
            });
    }
}
