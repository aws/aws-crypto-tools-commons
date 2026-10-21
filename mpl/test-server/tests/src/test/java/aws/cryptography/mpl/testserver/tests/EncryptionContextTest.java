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
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;
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
 * AllRawAES.dfy), plus AllDefaultCmm.dfy's surrogate-pair context.
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

    record Context(String name, Map<String, String> pairs) {
        @Override
        public String toString() {
            return name;
        }
    }

    static Map<String, String> identity(String... keys) {
        Map<String, String> map = new HashMap<>();
        for (String key : keys) map.put(key, key);
        return Map.copyOf(map);
    }

    static final List<Context> CONTEXTS = List.of(
        new Context("empty", Map.of()),
        new Context("basic", identity("a")),
        new Context("control", identity(NORMAL)),
        new Context("surrogate pair", identity(NORMAL, PSI)),
        new Context("surrogate pair alone", identity(PSI)),
        new Context("replacement char", identity(NORMAL, REPLACEMENT_CHAR)),
        // EncryptionContextUtils.dfy's "ascii" bin (1- and 2-byte characters).
        new Context("ascii bin single", identity("\u00B6")),
        new Context("ascii bin multiple", identity("1", "\u00A0", "U")),
        new Context("utf8 2-byte single", identity("\u0508")),
        new Context("utf8 2-byte multiple", identity("\u0100", "\u0518", "\u0508")),
        new Context("utf8 3-byte single", identity("\u2230")),
        new Context("utf8 3-byte multiple", identity("\u0800", "\u0DF4", "\u2230")),
        new Context("utf8 4-byte single", identity("\uD808\uDC00")),
        new Context("utf8 4-byte multiple", identity("\uD808\uDC00", "\uD80C\uDC23", "\uD80C\uDE69")));

    static Stream<Arguments> pairsByContext() {
        List<TargetPair> pairs = LanguageServerRegistry.shared().pairs();
        return CONTEXTS.stream()
            .flatMap(context -> pairs.stream().map(pair -> Arguments.of(context, pair)));
    }

    /** The non-empty contexts: an empty one has no value to alter. */
    static Stream<Arguments> pairsByNonEmptyContext() {
        return pairsByContext().filter(args -> !((Context) args.get()[0]).pairs().isEmpty());
    }

    @ParameterizedTest(name = "[encryption-context] round-trip {0} {1}")
    @MethodSource("pairsByContext")
    void roundTrip(Context context, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), context.pairs(), POLICY, SUITE);
        assertEquals(context.pairs(), encrypted.getEncryptionContext());

        DecryptMaterialsOutput decrypted = decrypt(
            MplTestServerClients.forEndpoint(pair.decryptEndpoint()), encrypted, POLICY);

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
        assertEquals(context.pairs(), decrypted.getEncryptionContext());
    }

    @ParameterizedTest(name = "[encryption-context] altered value rejected {0} {1}")
    @MethodSource("pairsByNonEmptyContext")
    void alteredContextRejected(Context context, TargetPair pair) {
        FeatureGate.require(FEATURES, pair);
        GetEncryptionMaterialsOutput encrypted = encrypt(
            MplTestServerClients.forEndpoint(pair.encryptEndpoint()), context.pairs(), POLICY, SUITE);

        Map<String, String> altered = new HashMap<>(encrypted.getEncryptionContext());
        String key = altered.keySet().iterator().next();
        altered.put(key, altered.get(key) + "x");

        MPLTestServerClient dec = MplTestServerClients.forEndpoint(pair.decryptEndpoint());
        String cmmId = createCmm(dec);
        assertThrows(MPLClientError.class, () -> dec.decryptMaterials(
            decryptMaterials(cmmId, encrypted, POLICY)
                .encryptionContext(altered)
                .build()));
    }
}
