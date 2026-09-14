package aws.cryptography.dbesdk.testserver.tests.transforms;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.client.model.GetItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryInput;
import aws.cryptography.dbesdk.testserver.client.model.QueryInputTransformInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInput;
import aws.cryptography.dbesdk.testserver.client.model.ScanInputTransformInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language pair tests for the modify-before Query / Scan input transforms
 * on a transforms client that has no beacon {@code SearchConfig}.
 *
 * <p>Bounded property: {@code QueryInputTransform} / {@code ScanInputTransform}
 * return the input unchanged when there are no beacons to rewrite. This is the
 * honest baseline for the beacon-rewrite operations — both ops are modeled but,
 * before this class, exercised by no Test Server test (only their output duals
 * were). The Dafny suite covers it directly
 * ({@code QueryTransform.dfy}: {@code TestQueryInputPassthrough};
 * {@code ScanTransform.dfy}: {@code TestScanInputPassthrough};
 * {@code FilterExpr.dfy}: {@code TestNoBeacons}).
 *
 * <p>The transforms client is built with the standard (no-search) config, so no
 * keystore is involved. The oracle is that the transformed input equals the
 * submitted input.
 *
 * <p>Each transform runs on the pair's encrypt endpoint (the request side), so
 * across the pair matrix every language server is exercised as the target.
 */
class SearchInputTransformPassthroughTests {

    @ParameterizedTest(name = "[transform] QueryInputTransform passes through without beacon config {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryInputTransformWithoutBeaconConfigPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        QueryInput sdkInput = QueryInput.builder().tableName(TABLE).build();
        QueryInput transformed = client.queryInputTransform(
            QueryInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(sdkInput)
                .build()).getTransformedInput();
        assertEquals(sdkInput, transformed,
            "QueryInputTransform without a beacon config must return the input unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] ScanInputTransform passes through without beacon config {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanInputTransformWithoutBeaconConfigPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        ScanInput sdkInput = ScanInput.builder().tableName(TABLE).build();
        ScanInput transformed = client.scanInputTransform(
            ScanInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(sdkInput)
                .build()).getTransformedInput();
        assertEquals(sdkInput, transformed,
            "ScanInputTransform without a beacon config must return the input unchanged on " + pair);
    }

    @ParameterizedTest(name = "[transform] GetItemInputTransform passes through without beacon config {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void getItemInputTransformWithoutBeaconConfigPassesThrough(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        GetItemInput sdkInput = GetItemInput.builder()
            .tableName(TABLE)
            .key(Map.of("PK", AttributeValue.builder().s("k").build()))
            .build();
        GetItemInput transformed = client.getItemInputTransform(
            GetItemInputTransformInput.builder()
                .clientId(clientId)
                .sdkInput(sdkInput)
                .build()).getTransformedInput();
        assertEquals(sdkInput, transformed,
            "GetItemInputTransform without a beacon config must return the input unchanged on " + pair);
    }

    /**
     * On the same no-beacon transforms client, the modify-before input transform
     * still applies the pre-beacon expression-length guard (Dafny
     * {@code DDBSupport.dfy}: {@code TestQueryInputForBeaconsRejectsLongKeyExpression}):
     * {@code ValidateExpressionLength} runs at the top of {@code QueryInputForBeacons},
     * before the no-beacon passthrough return, so a {@code KeyConditionExpression}
     * over 4096 characters is rejected with the modeled length error.
     *
     * <p>java-v3 pins the published {@code aws-database-encryption-sdk-dynamodb}
     * 3.8.1, which predates this guard, so it does not enforce the limit (the
     * over-length expression bypasses the absent guard and reaches the DDB
     * parser). That version skew is the declared known bug
     * {@code java-3-8-1-missing-expression-length-guard}: net-v4 and rust-v1
     * assert the guard, java-v3 is a visible skip, and bumping java-v3's pinned
     * version past the guard makes the gate fail loudly so the entry is retired.
     */
    @ParameterizedTest(name = "[transform] QueryInputTransform rejects an over-4096-char KeyConditionExpression {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void queryInputTransformRejectsOverLengthKeyConditionExpression(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        String overLimit = " ".repeat(4097);
        KnownBugGate.gateDeclared(
            "java-3-8-1-missing-expression-length-guard",
            pair.encryptTarget().language(),
            () -> {
                DBESDKClientError error = assertThrows(DBESDKClientError.class,
                    () -> client.queryInputTransform(QueryInputTransformInput.builder()
                        .clientId(clientId)
                        .sdkInput(QueryInput.builder()
                            .tableName(TABLE).keyConditionExpression(overLimit).build())
                        .build()),
                    "a KeyConditionExpression over 4096 characters must be rejected on " + pair);
                assertTrue(
                    error.getMessage() != null
                        && error.getMessage().contains("exceeds maximum length of 4096"),
                    "the rejection must name the 4096-character limit; got: "
                        + error.getMessage() + " on " + pair);
            });
    }

    /**
     * Scan-path counterpart of
     * {@link #queryInputTransformRejectsOverLengthKeyConditionExpression} (Dafny
     * {@code DDBSupport.dfy}: {@code TestScanInputForBeaconsRejectsLongFilterExpression}):
     * a {@code FilterExpression} over 4096 characters is rejected. Same java-v3
     * version-skew known bug ({@code java-3-8-1-missing-expression-length-guard}).
     */
    @ParameterizedTest(name = "[transform] ScanInputTransform rejects an over-4096-char FilterExpression {0}")
    @MethodSource("aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers#pairs")
    void scanInputTransformRejectsOverLengthFilterExpression(TargetPair pair) {
        FeatureGate.require(Set.of("ddb-transforms"), pair);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String clientId = DbeTestHelpers.newTransformsClient(client, TABLE);
        String overLimit = " ".repeat(4097);
        KnownBugGate.gateDeclared(
            "java-3-8-1-missing-expression-length-guard",
            pair.encryptTarget().language(),
            () -> {
                DBESDKClientError error = assertThrows(DBESDKClientError.class,
                    () -> client.scanInputTransform(ScanInputTransformInput.builder()
                        .clientId(clientId)
                        .sdkInput(ScanInput.builder()
                            .tableName(TABLE).filterExpression(overLimit).build())
                        .build()),
                    "a FilterExpression over 4096 characters must be rejected on " + pair);
                assertTrue(
                    error.getMessage() != null
                        && error.getMessage().contains("exceeds maximum length of 4096"),
                    "the rejection must name the 4096-character limit; got: "
                        + error.getMessage() + " on " + pair);
            });
    }
}
