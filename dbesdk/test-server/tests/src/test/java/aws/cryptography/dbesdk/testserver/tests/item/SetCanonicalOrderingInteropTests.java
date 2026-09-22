package aws.cryptography.dbesdk.testserver.tests.item;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertAttributeEquals;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language interop for canonical Set element ordering and Map key
 * ordering on {@code ENCRYPT_AND_SIGN} values. Cohesive property: DBE
 * canonically re-orders Set elements and Map keys before signing, using
 * <em>UTF-16 binary order</em> for text and lexicographic (prefix-aware) order
 * for binary — identically across languages. A cross-language round-trip only
 * verifies when both sides produce the same canonical order, so decrypt success
 * is the discriminating oracle.
 *
 * <p>The inputs are chosen so a wrong ordering rule diverges observably:
 * <ul>
 *   <li>an astral-plane code point ({@code U+10002}) sorts <em>after</em> the
 *       BMP {@code U+FF61} by UTF-8 byte order but <em>before</em> it by UTF-16
 *       binary order — so a UTF-8-order bug breaks exactly this cross-decrypt
 *       (String Set and Map keys);</li>
 *   <li>a binary set {@code [[1],[2],[1,0]]} distinguishes prefix-aware
 *       lexicographic order ({@code [1] < [1,0] < [2]}) from a naive
 *       length-then-content order.</li>
 * </ul>
 *
 * <p>Existing coverage ({@code DynamoDbAttributeSerializationInteropTests})
 * uses ASCII sets whose insertion order already equals canonical order (where
 * UTF-8 and UTF-16 order coincide), so none of these ordering edges are
 * otherwise exercised. Vectors are from {@code DynamoToStruct.dfy}
 * ({@code TestSortSSAttr}, {@code TestSortBSAttr}, {@code TestSortMapKeys},
 * {@code TestSetsInListAreSorted}, {@code TestSetsInMapAreSorted}).
 */
class SetCanonicalOrderingInteropTests {

    private static final String VALUE = "value";

    /** "&" (U+0026), "｡" (U+FF61, BMP), "𐀂" (U+10002, astral). */
    private static final String AMP = "&";
    private static final String BMP = "\uFF61";
    private static final String ASTRAL = "\uD800\uDC02";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static Map<String, CryptoAction> pkPlusEncryptedValue() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(VALUE, CryptoAction.ENCRYPT_AND_SIGN);
        return actions;
    }

    /** Encrypt {PK, VALUE=value} on one endpoint, decrypt on the other, assert VALUE preserved. */
    private static void assertValueRoundTrips(TargetPair pair, AttributeValue value) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, CryptoAction> actions = pkPlusEncryptedValue();
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("set-key").build());
        plaintext.put(VALUE, value);
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        DecryptItemOutput decrypted = decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
        assertAttributeEquals(value, decrypted.getPlaintextItem().get(VALUE), "set", pair);
    }

    private static ByteBuffer bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return ByteBuffer.wrap(out);
    }

    @ParameterizedTest(name = "string set UTF-16 astral order {0}")
    @MethodSource("testPairs")
    void stringSetUtf16AstralOrder(TargetPair pair) {
        assertValueRoundTrips(pair,
            AttributeValue.builder().ss(List.of(AMP, BMP, ASTRAL)).build());
    }

    @ParameterizedTest(name = "binary set prefix order {0}")
    @MethodSource("testPairs")
    void binarySetPrefixOrder(TargetPair pair) {
        // [1] < [1,0] < [2] : prefix-aware lexicographic, supplied out of order.
        assertValueRoundTrips(pair,
            AttributeValue.builder().bs(List.of(bytes(1), bytes(2), bytes(1, 0))).build());
    }

    @ParameterizedTest(name = "sets inside list independently sorted {0}")
    @MethodSource("testPairs")
    void setsInsideListSorted(TargetPair pair) {
        AttributeValue list = AttributeValue.builder().l(List.of(
            AttributeValue.builder().ns(List.of("2", "1", "10")).build(),
            AttributeValue.builder().ss(List.of(AMP, BMP, ASTRAL)).build(),
            AttributeValue.builder().bs(List.of(bytes(1), bytes(2), bytes(1, 0))).build()))
            .build();
        assertValueRoundTrips(pair, list);
    }

    @ParameterizedTest(name = "sets inside map independently sorted {0}")
    @MethodSource("testPairs")
    void setsInsideMapSorted(TargetPair pair) {
        Map<String, AttributeValue> map = new LinkedHashMap<>();
        map.put("a", AttributeValue.builder().ss(List.of(AMP, BMP, ASTRAL)).build());
        map.put("b", AttributeValue.builder().ns(List.of("2", "1", "10")).build());
        map.put("c", AttributeValue.builder().bs(List.of(bytes(1), bytes(2), bytes(1, 0))).build());
        assertValueRoundTrips(pair, AttributeValue.builder().m(map).build());
    }

    @ParameterizedTest(name = "map keys UTF-16 astral order {0}")
    @MethodSource("testPairs")
    void mapKeysUtf16AstralOrder(TargetPair pair) {
        Map<String, AttributeValue> map = new LinkedHashMap<>();
        map.put(AMP, AttributeValue.builder().s("v-amp").build());
        map.put(BMP, AttributeValue.builder().s("v-bmp").build());
        map.put(ASTRAL, AttributeValue.builder().s("v-astral").build());
        assertValueRoundTrips(pair, AttributeValue.builder().m(map).build());
    }
}
