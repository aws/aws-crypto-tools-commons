package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.esdk.testserver.tests.EsdkClientConfigs.Scenario;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Per-scenario blob round-trip coverage for the offline Java hardening pass
 * (Task 14.3, design "Per-scenario config coverage for the Java hardening pass").
 *
 * <p>This is a deterministic JUnit 5 <strong>parameterized</strong> test: every
 * offline keyring/CMM/algorithm-suite {@link Scenario} from {@link
 * EsdkClientConfigs#scenarios()} appears as its OWN named execution in the test
 * report and is <strong>guaranteed to run</strong> on every pass. This is the
 * mechanism that guarantees per-config coverage; the jqwik {@link
 * BlobRoundTripPropertyTest} (Property 1) complements it by stressing the
 * arbitrary-plaintext input space, but is explicitly not the coverage guarantee.
 *
 * <p>Each execution asserts {@code decrypt(encrypt(x)) == x} byte-for-byte
 * (Requirements 4.2, 4.3, 4.4) over a small, FIXED representative set of
 * plaintexts — the empty plaintext, a small text blob, and a larger binary blob —
 * driving real config marshalling (the tagged-union config surface, incl. the
 * recursive multi-keyring nesting of Property 7) and the real ESDK Java code paths
 * over the real rpcv2Cbor HTTP hop via the ONE generated Java Test_Client. Fully
 * offline: no AWS/KMS/network.
 *
 * <p>The {@link EndpointPair} is resolved once for the whole class ({@link
 * BeforeAll}/{@link AfterAll}) — for the offline Java hardening pass that pair is
 * the in-process Java Language_Server as both the encrypt and decrypt endpoint —
 * mirroring the lifecycle of the existing blob/stream Tests.
 */
class BlobRoundTripScenariosTest {

    private static EndpointPair pair;

    @BeforeAll
    static void bootEndpoints() {
        pair = EndpointPair.resolve(RuntimeEndpointConfig.fromRuntime());
    }

    @AfterAll
    static void shutdownEndpoints() {
        if (pair != null) {
            pair.close();
        }
    }

    /**
     * The offline, round-trip-compatible scenarios. Each becomes one named
     * parameterized execution; {@link Scenario#toString()} supplies the label.
     */
    static List<Scenario> scenarios() {
        return EsdkClientConfigs.scenarios();
    }

    /**
     * A small, fixed, representative set of plaintexts exercised by every
     * scenario: the empty plaintext (Requirement 4.4), a small text blob, and a
     * larger binary blob (deterministic content, not random).
     */
    private static List<byte[]> representativePlaintexts() {
        byte[] empty = new byte[0];
        byte[] smallText =
            "esdk-test-server per-scenario round-trip plaintext".getBytes(StandardCharsets.UTF_8);
        byte[] largerBinary = new byte[8 * 1024 + 13];
        for (int i = 0; i < largerBinary.length; i++) {
            largerBinary[i] = (byte) (i * 31 + 7);
        }
        return List.of(empty, smallText, largerBinary);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    void blobRoundTripPreservesPlaintextForScenario(Scenario scenario) {
        // Supply every encryption-context key the scenario's CMM requires (a
        // Required-Encryption-Context CMM drops these from the header and demands
        // them again on decrypt). The same context is used on encrypt and decrypt
        // so the round trip is well-formed; empty for scenarios with no required
        // keys.
        Map<String, String> ec = new LinkedHashMap<>();
        for (String requiredKey : scenario.requiredEncryptionContextKeys()) {
            ec.put(requiredKey, "required-value-for-" + requiredKey);
        }

        for (byte[] plaintext : representativePlaintexts()) {
            byte[] recovered = BlobRoundTrip.run(pair, plaintext, scenario, ec);
            assertArrayEquals(plaintext, recovered,
                "decrypt(encrypt(plaintext)) must equal the original plaintext "
                    + "(scenario: " + scenario.label() + ", plaintext length: "
                    + plaintext.length + ")");
        }
    }
}
