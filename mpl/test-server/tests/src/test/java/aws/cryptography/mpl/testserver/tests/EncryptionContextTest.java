package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.bytes;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.createCmm;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.decrypt;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.decryptMaterials;
import static aws.cryptography.mpl.testserver.tests.DefaultCmmFixture.encrypt;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CommitmentPolicy;
import aws.cryptography.mpl.testserver.client.model.DecryptMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.GetEncryptionMaterialsOutput;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.EncryptionContextInputs;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Encryption contexts across the UTF-8 encoding widths, through the Default CMM
 * and Raw AES keyring, across the pairwise matrix. The Raw AES keyring
 * authenticates the serialized context as AAD, so the two targets must agree on
 * its UTF-8 serialization byte for byte, and a context altered after encrypt
 * must fail the unwrap.
 *
 * <p>The contexts are the sets in the Dafny MPL test vectors'
 * EncryptionContextUtils.dfy (crossed with the Raw AES keyring in
 * AllRawAES.dfy), plus AllDefaultCmm.dfy's surrogate-pair context,
 * plus the shared {@link EncryptionContextInputs#validEncryptionContexts()}, which has the empty context.
 */
public class EncryptionContextTest {

    private static final Set<String> FEATURES = Set.of("raw-aes", "default-cmm");
    private static final AlgorithmSuiteId SUITE = AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    private static final CommitmentPolicy POLICY = CommitmentPolicy.ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

    /** "normal" followed by U+D000: EncryptionContextUtils.dfy's {@code normal}. */
    private static final String NORMAL = "normal\uD000";
    /** U+10002 (a surrogate pair in UTF-16, 4 bytes in UTF-8). */
    private static final String PSI = "\uD800\uDC02";
    private static final String REPLACEMENT_CHAR = "\uFFFD";

    static Map<String, String> identity(String... keys) {
        Map<String, String> map = new HashMap<>();
        for (String key : keys) map.put(key, key);
        return Map.copyOf(map);
    }

    static final List<Example<Map<String, String>>> DAFNY_CONTEXTS = List.of(
        new Example<>("basic", identity("a")),
        new Example<>("control", identity(NORMAL)),
        new Example<>("surrogate pair", identity(NORMAL, PSI)),
        new Example<>("surrogate pair alone", identity(PSI)),
        new Example<>("replacement char", identity(NORMAL, REPLACEMENT_CHAR)),
        // EncryptionContextUtils.dfy's "ascii" bin (1- and 2-byte characters).
        new Example<>("ascii bin single", identity("\u00B6")),
        new Example<>("ascii bin multiple", identity("1", "\u00A0", "U")),
        new Example<>("utf8 2-byte single", identity("\u0508")),
        new Example<>("utf8 2-byte multiple", identity("\u0100", "\u0518", "\u0508")),
        new Example<>("utf8 3-byte single", identity("\u2230")),
        new Example<>("utf8 3-byte multiple", identity("\u0800", "\u0DF4", "\u2230")),
        new Example<>("utf8 4-byte single", identity("\uD808\uDC00")),
        new Example<>("utf8 4-byte multiple", identity("\uD808\uDC00", "\uD80C\uDC23", "\uD80C\uDE69")));

    static List<Example<Map<String, String>>> contexts() {
        List<Example<Map<String, String>>> contexts = new ArrayList<>(DAFNY_CONTEXTS);
        contexts.addAll(EncryptionContextInputs.validEncryptionContexts());
        return contexts;
    }

    static Stream<Arguments> pairsByContext() {
        return ExampleCases.withEachPair(contexts());
    }

    /** The non-empty contexts: an empty one has no value to alter. */
    static Stream<Arguments> pairsByNonEmptyContext() {
        return ExampleCases.withEachPair(contexts().stream().filter(context -> !context.value().isEmpty()).toList());
    }

    @ParameterizedTest(name = "[encryption-context] round-trip {0} {1}")
    @MethodSource("pairsByContext")
    void roundTrip(Example<Map<String, String>> context, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), context.value(), POLICY, SUITE);
        assertEquals(context.value(), encrypted.getEncryptionContext());

        DecryptMaterialsOutput decrypted = decrypt(
            MplTestServerClients.forEndpoint(pair.decryptEndpoint()), encrypted, POLICY);

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(context.value(), decrypted.getEncryptionContext());
    }

    @ParameterizedTest(name = "[encryption-context] altered value rejected {0} {1}")
    @MethodSource("pairsByNonEmptyContext")
    void alteredContextRejected(Example<Map<String, String>> context, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), context.value(), POLICY, SUITE);

        Map<String, String> altered = EncryptionContextInputs.withOneValueChanged(encrypted.getEncryptionContext());

        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        String cmmId = createCmm(dec);
        assertThrows(MPLClientError.class, () -> dec.decryptMaterials(
            decryptMaterials(cmmId, encrypted, POLICY)
                .encryptionContext(altered)
                .build()));
    }
}
