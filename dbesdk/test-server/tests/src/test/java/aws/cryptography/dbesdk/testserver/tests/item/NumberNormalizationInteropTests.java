package aws.cryptography.dbesdk.testserver.tests.item;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.assertAttributeEquals;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.client.model.EncryptItemInput;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language interop for DDB Number normalization on an
 * {@code ENCRYPT_AND_SIGN} attribute. Cohesive property: DBE normalizes every
 * Number it serializes to a single canonical form (leading/trailing-zero
 * stripping, exponent expansion, {@code -0}→{@code 0}), applies that
 * normalization at every position (top-level, in a Number Set, and inside List
 * / Map containers), and rejects a malformed or out-of-range Number at encrypt.
 *
 * <p>Because the value is encrypted, the plaintext DBE serializes is the
 * <em>normalized</em> form, so it is what {@code DecryptItem} recovers — the
 * canonical form is directly observable. The cross-language round-trip
 * additionally proves both languages normalize identically: a divergent
 * normalization would sign different bytes and fail cross-decrypt.
 *
 * <p>All Number vectors are lifted verbatim from the Dafny
 * {@code NormalizeNumber.dfy} known-answer suite
 * ({@code TestExamples}, {@code TestExtremes}, {@code TestFailures}) and
 * {@code DynamoToStruct.dfy} ({@code TestNormalizeN*}, {@code TestSortNSAfterNormalize}).
 *
 * <p>Existing coverage ({@code DynamoDbAttributeSerializationInteropTests})
 * uses already-canonical Numbers, so none of these normalization edges are
 * otherwise exercised.
 */
class NumberNormalizationInteropTests {

    private static final String VALUE = "value";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    private static Map<String, CryptoAction> pkPlusEncryptedValue() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        actions.put(VALUE, CryptoAction.ENCRYPT_AND_SIGN);
        return actions;
    }

    /** Encrypt an item {PK, VALUE=value} on one endpoint, decrypt on the other. */
    private static DecryptItemOutput roundTripValue(TargetPair pair, AttributeValue value) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient =
            DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        Map<String, CryptoAction> actions = pkPlusEncryptedValue();
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("num-key").build());
        plaintext.put(VALUE, value);
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        return decryptClient.decryptItem(DecryptItemInput.builder()
            .clientId(decryptClientId).encryptedItem(item).build());
    }

    /** Assert VALUE decrypts to {@code expected} across the pair. */
    private static void assertValueNormalizesTo(
            TargetPair pair, AttributeValue input, AttributeValue expected) {
        DecryptItemOutput decrypted = roundTripValue(pair, input);
        assertAttributeEquals(expected, decrypted.getPlaintextItem().get(VALUE), "N", pair);
    }

    /** Encrypt-only: assert VALUE causes EncryptItem to fail on the encrypt target. */
    private static void assertValueRejectedOnEncrypt(TargetPair pair, AttributeValue value) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = newKmsClient(encryptClient, TABLE, PK, pkPlusEncryptedValue(), List.of());
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>();
        plaintext.put(PK, AttributeValue.builder().s("num-key").build());
        plaintext.put(VALUE, value);
        assertThrows(DBESDKClientError.class, () -> encryptClient.encryptItem(
            EncryptItemInput.builder().clientId(clientId).plaintextItem(plaintext).build()),
            "a malformed/out-of-range Number must be rejected at encrypt on " + pair);
    }

    @ParameterizedTest(name = "top-level number normalized {0}")
    @MethodSource("testPairs")
    void topLevelNumberNormalized(TargetPair pair) {
        // NormalizeNumber.dfy TestExamples: "1.2e2" -> "120"
        assertValueNormalizesTo(pair,
            AttributeValue.builder().n("1.2e2").build(),
            AttributeValue.builder().n("120").build());
    }

    @ParameterizedTest(name = "number set normalized {0}")
    @MethodSource("testPairs")
    void numberSetNormalized(TargetPair pair) {
        // DynamoToStruct.dfy TestNormalizeNInSet: NS(["001.00"]) -> NS(["1"])
        assertValueNormalizesTo(pair,
            AttributeValue.builder().ns(List.of("001.00")).build(),
            AttributeValue.builder().ns(List.of("1")).build());
    }

    @ParameterizedTest(name = "number in list normalized {0}")
    @MethodSource("testPairs")
    void numberInListNormalized(TargetPair pair) {
        // DynamoToStruct.dfy TestNormalizeNInList: L=[N("001.00")] -> L=[N("1")]
        assertValueNormalizesTo(pair,
            AttributeValue.builder().l(List.of(AttributeValue.builder().n("001.00").build())).build(),
            AttributeValue.builder().l(List.of(AttributeValue.builder().n("1").build())).build());
    }

    @ParameterizedTest(name = "number in map normalized {0}")
    @MethodSource("testPairs")
    void numberInMapNormalized(TargetPair pair) {
        // DynamoToStruct.dfy TestNormalizeNInMap: M={keyA:N("001.00")} -> M={keyA:N("1")}
        Map<String, AttributeValue> in = new LinkedHashMap<>();
        in.put("keyA", AttributeValue.builder().n("001.00").build());
        Map<String, AttributeValue> out = new LinkedHashMap<>();
        out.put("keyA", AttributeValue.builder().n("1").build());
        assertValueNormalizesTo(pair,
            AttributeValue.builder().m(in).build(),
            AttributeValue.builder().m(out).build());
    }

    @ParameterizedTest(name = "number set sorted after normalize {0}")
    @MethodSource("testPairs")
    void numberSetSortedAfterNormalize(TargetPair pair) {
        // DynamoToStruct.dfy TestSortNSAfterNormalize: ["1","02","10"] -> canonical {"1","2","10"}
        // (compared order-independently; the canonical sort ["1","10","2"] is
        // what makes both languages agree on the signed bytes).
        assertValueNormalizesTo(pair,
            AttributeValue.builder().ns(List.of("1", "02", "10")).build(),
            AttributeValue.builder().ns(List.of("1", "2", "10")).build());
    }

    @ParameterizedTest(name = "canonical forms round-trip {0}")
    @MethodSource("testPairs")
    void canonicalFormsRoundTrip(TargetPair pair) {
        // NormalizeNumber.dfy TestExamples: exponent/leading-zero/negative-zero rules.
        assertValueNormalizesTo(pair,
            AttributeValue.builder().n("00012.34").build(),
            AttributeValue.builder().n("12.34").build());
        assertValueNormalizesTo(pair,
            AttributeValue.builder().n("-0").build(),
            AttributeValue.builder().n("0").build());
        assertValueNormalizesTo(pair,
            AttributeValue.builder().n("123.456e-1").build(),
            AttributeValue.builder().n("12.3456").build());
    }

    @ParameterizedTest(name = "extreme precision/magnitude boundary {0}")
    @MethodSource("testPairs")
    void extremePrecisionAndMagnitudeBoundary(TargetPair pair) {
        // NormalizeNumber.dfy TestExtremes: 38 digits of precision accepted (canonical == itself)...
        String maxPrecision = "123456789.01234567890123456789012345678"; // 38 significant digits
        assertValueNormalizesTo(pair,
            AttributeValue.builder().n(maxPrecision).build(),
            AttributeValue.builder().n(maxPrecision).build());
        // ...39 digits rejected.
        assertValueRejectedOnEncrypt(pair,
            AttributeValue.builder().n("123456789.012345678901234567890123456789").build());
    }

    @ParameterizedTest(name = "malformed number rejected on encrypt {0}")
    @MethodSource("testPairs")
    void malformedNumberRejectedOnEncrypt(TargetPair pair) {
        // NormalizeNumber.dfy TestFailures: "1.2.3" is not a valid number.
        assertValueRejectedOnEncrypt(pair, AttributeValue.builder().n("1.2.3").build());
    }
}
