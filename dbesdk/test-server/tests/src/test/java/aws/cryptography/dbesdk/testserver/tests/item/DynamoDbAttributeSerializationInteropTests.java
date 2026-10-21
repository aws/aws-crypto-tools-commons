package aws.cryptography.dbesdk.testserver.tests.item;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertAttributeEquals;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * DDB attribute-type fidelity for the non-scalar types: string/number/binary
 * sets ({@code SS}/{@code NS}/{@code BS}), lists ({@code L}), and maps
 * ({@code M}), including recursive nesting. Cohesive property: "every DDB
 * attribute type survives an encrypt/decrypt round-trip unchanged", exercised
 * across the full cross-language pair matrix.
 *
 * <p>Distinct from {@link ItemEncryptionBoundaryBehaviorTests} (unusual item <em>shapes</em>:
 * size, emptiness) — this file's property is <em>type coverage</em>. The scalar
 * types are already covered by the canonical-plaintext round-trips in the
 * V1/V2 encryption-context files, so they are not repeated here.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #stringSetRoundTrip} — {@code SS}</li>
 *   <li>{@link #numberSetRoundTrip} — {@code NS}</li>
 *   <li>{@link #binarySetRoundTrip} — {@code BS}</li>
 *   <li>{@link #nestedListRoundTrip} — {@code L} of mixed scalars, nested {@code L}/{@code M}</li>
 *   <li>{@link #nestedMapRoundTrip} — {@code M} of mixed scalars and a nested {@code M}</li>
 *   <li>{@link #signOnlySetSurvivesElementReorder} — regression for the
 *       {@code SIGN_ONLY} Set canonicalization fix (v3.1.1 "DecryptWithPermute",
 *       <a href="https://github.com/aws/aws-database-encryption-sdk-dynamodb/security/advisories/GHSA-72fp-w44g-625q">GHSA-72fp-w44g-625q</a>)</li>
 *   <li>{@link #mixedScalarAndCollectionItemRoundTrip} — one item mixing scalar and collection types</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 7 assertions × pairs²}.
 */
class DynamoDbAttributeSerializationInteropTests {

    /** Attribute holding the type under test; ENCRYPT_AND_SIGN unless noted. */
    private static final String VALUE = "value";

    /** SIGN_ONLY set attribute for the reorder regression. */
    private static final String TAGS = "tags";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static Map<String, CryptoAction> pkPlus(String attr, CryptoAction action) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(attr, action);
        return actions;
    }

    /** Encrypt {@code plaintext} on one endpoint, decrypt on the other. */
    private static DecryptItemOutput roundTrip(
            TargetPair pair, Map<String, CryptoAction> actions, Map<String, AttributeValue> plaintext) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        return decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
    }

    @ParameterizedTest(name = "string set round-trip {0}")
    @MethodSource("testPairs")
    void stringSetRoundTrip(TargetPair pair) {
        AttributeValue set =
            AttributeValue.builder().ss(List.of("alpha", "beta", "gamma")).build();
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("ss-key").build());
        plaintext.put(VALUE, set);

        DecryptItemOutput decrypted = roundTrip(pair, pkPlus(VALUE, CryptoAction.ENCRYPT_AND_SIGN), plaintext);
        //= specification/dynamodb-encryption-client/ddb-attribute-serialization.md#set
        //= type=test
        //= reason=cross-language round-trip fails if the Set wire format is wrong
        //# A Set MUST be serialized as:
        assertAttributeEquals(set, decrypted.getPlaintextItem().get(VALUE), "SS", pair);
    }

    @ParameterizedTest(name = "number set round-trip {0}")
    @MethodSource("testPairs")
    void numberSetRoundTrip(TargetPair pair) {
        AttributeValue set = AttributeValue.builder().ns(List.of("1", "2", "3", "-4.5")).build();
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("ns-key").build());
        plaintext.put(VALUE, set);

        DecryptItemOutput decrypted = roundTrip(pair, pkPlus(VALUE, CryptoAction.ENCRYPT_AND_SIGN), plaintext);
        //= specification/dynamodb-encryption-client/ddb-attribute-serialization.md#set
        //= type=test
        //= reason=cross-language round-trip fails if the Set wire format is wrong
        //# A Set MUST be serialized as:
        assertAttributeEquals(set, decrypted.getPlaintextItem().get(VALUE), "NS", pair);
    }

    @ParameterizedTest(name = "binary set round-trip {0}")
    @MethodSource("testPairs")
    void binarySetRoundTrip(TargetPair pair) {
        AttributeValue set = AttributeValue.builder()
            .bs(List.of(
                ByteBuffer.wrap(new byte[] {0x00, 0x01}),
                ByteBuffer.wrap(new byte[] {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD})))
            .build();
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("bs-key").build());
        plaintext.put(VALUE, set);

        DecryptItemOutput decrypted = roundTrip(pair, pkPlus(VALUE, CryptoAction.ENCRYPT_AND_SIGN), plaintext);
        //= specification/dynamodb-encryption-client/ddb-attribute-serialization.md#set
        //= type=test
        //= reason=cross-language round-trip fails if the Set wire format is wrong
        //# A Set MUST be serialized as:
        assertAttributeEquals(set, decrypted.getPlaintextItem().get(VALUE), "BS", pair);
    }

    @ParameterizedTest(name = "nested list round-trip {0}")
    @MethodSource("testPairs")
    void nestedListRoundTrip(TargetPair pair) {
        Map<String, AttributeValue> innerMap = new LinkedHashMap<>();
        innerMap.put("k", AttributeValue.builder().s("v").build());
        AttributeValue list = AttributeValue.builder()
            .l(List.of(
                AttributeValue.builder().s("s0").build(),
                AttributeValue.builder().n("42").build(),
                AttributeValue.builder().bool(true).build(),
                AttributeValue.builder().l(List.of(
                    AttributeValue.builder().s("nested0").build(),
                    AttributeValue.builder().n("7").build())).build(),
                AttributeValue.builder().m(innerMap).build()))
            .build();
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("l-key").build());
        plaintext.put(VALUE, list);

        DecryptItemOutput decrypted = roundTrip(pair, pkPlus(VALUE, CryptoAction.ENCRYPT_AND_SIGN), plaintext);
        //= specification/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
        //= type=test
        //= reason=cross-language round-trip fails if list element order is not preserved
        //# The order of these serialized list entries MUST match
        //# the order of the entries in the original list.
        assertAttributeEquals(list, decrypted.getPlaintextItem().get(VALUE), "L", pair);
    }

    @ParameterizedTest(name = "nested map round-trip {0}")
    @MethodSource("testPairs")
    void nestedMapRoundTrip(TargetPair pair) {
        Map<String, AttributeValue> inner = new LinkedHashMap<>();
        inner.put("deep", AttributeValue.builder().s("value").build());
        inner.put("count", AttributeValue.builder().n("9").build());
        Map<String, AttributeValue> outer = new LinkedHashMap<>();
        outer.put("name", AttributeValue.builder().s("widget").build());
        outer.put("flag", AttributeValue.builder().bool(false).build());
        outer.put("child", AttributeValue.builder().m(inner).build());
        AttributeValue map = AttributeValue.builder().m(outer).build();
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("m-key").build());
        plaintext.put(VALUE, map);

        DecryptItemOutput decrypted = roundTrip(pair, pkPlus(VALUE, CryptoAction.ENCRYPT_AND_SIGN), plaintext);
        //= specification/dynamodb-encryption-client/ddb-attribute-serialization.md#map-attribute
        //= type=test
        //= reason=cross-language round-trip fails if the Map wire format is wrong
        //# Map MUST be serialized as:
        assertAttributeEquals(map, decrypted.getPlaintextItem().get(VALUE), "M", pair);
    }

    /**
     * Regression for the SIGN_ONLY-Set canonicalization fix (DBE v3.1.1,
     * "DecryptWithPermute", GHSA-72fp-w44g-625q): before the fix, a Set marked
     * SIGN_ONLY could fail signature validation on read when DynamoDB returned
     * its elements in a different order than they were written, even with
     * identical values. The fix canonicalizes Set element order identically on
     * write and read.
     *
     * <p>A SIGN_ONLY Set is authenticated but not encrypted, so it stays as a
     * plaintext {@code SS} on the wire. This test reorders that Set's elements
     * in the encrypted item before decrypt — simulating DynamoDB's undefined
     * return order — and asserts decrypt still verifies and preserves the Set.
     */
    @ParameterizedTest(name = "SIGN_ONLY set survives element reorder {0}")
    @MethodSource("testPairs")
    void signOnlySetSurvivesElementReorder(TargetPair pair) {
        List<String> elements = List.of("red", "green", "blue", "yellow");
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("signed-set-key").build());
        plaintext.put(TAGS, AttributeValue.builder().ss(elements).build());

        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, CryptoAction> actions = pkPlus(TAGS, CryptoAction.SIGN_ONLY);
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);

        // The SIGN_ONLY set is plaintext on the wire — reverse its element order
        // to model DynamoDB's undefined Set ordering on read.
        AttributeValue onWire = item.get(TAGS);
        assertTrue(onWire.hasSs(), "SIGN_ONLY set must remain a plaintext SS on the wire on " + pair);
        List<String> reordered = new ArrayList<>(onWire.getSs());
        java.util.Collections.reverse(reordered);
        item.put(TAGS, AttributeValue.builder().ss(reordered).build());

        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        //= specification/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //= reason=reordered on-wire SS still verifies because entries are canonically re-sorted before signing
        //# Entries in a String Set MUST be ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
        assertAttributeEquals(
            AttributeValue.builder().ss(elements).build(),
            decrypted.getPlaintextItem().get(TAGS),
            "SIGN_ONLY SS after reorder", pair);
    }

    @ParameterizedTest(name = "mixed scalar and collection item round-trip {0}")
    @MethodSource("testPairs")
    void mixedScalarAndCollectionItemRoundTrip(TargetPair pair) {
        Map<String, AttributeValue> nested = new LinkedHashMap<>();
        nested.put("inner", AttributeValue.builder().n("100").build());
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("mixed-key").build());
        plaintext.put("str", AttributeValue.builder().s("scalar").build());
        plaintext.put("num", AttributeValue.builder().n("3.14").build());
        plaintext.put("set", AttributeValue.builder().ss(List.of("x", "y")).build());
        plaintext.put("list", AttributeValue.builder()
            .l(List.of(AttributeValue.builder().s("a").build(),
                       AttributeValue.builder().bool(false).build())).build());
        plaintext.put("map", AttributeValue.builder().m(nested).build());

        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put("str", CryptoAction.SIGN_ONLY);
        actions.put("num", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("set", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("list", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("map", CryptoAction.ENCRYPT_AND_SIGN);

        DecryptItemOutput decrypted = roundTrip(pair, actions, plaintext);
        for (Map.Entry<String, AttributeValue> e : plaintext.entrySet()) {
            assertAttributeEquals(
                e.getValue(), decrypted.getPlaintextItem().get(e.getKey()),
                "mixed[" + e.getKey() + "]", pair);
        }
    }

    // Deep AttributeValue equality lives in DbeTestHelpers.assertAttributeEquals
    // (statically imported), shared with the number/set canonicalization suites.
}
