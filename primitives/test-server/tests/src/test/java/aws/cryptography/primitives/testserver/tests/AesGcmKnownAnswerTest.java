package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.AesAlgorithm;
import aws.cryptography.primitives.testserver.client.model.AesDecryptInput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptInput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptOutput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * AES-GCM known answers, per target: encrypt must produce exactly the expected
 * ciphertext and tag, and decrypt must recover the plaintext from them.
 *
 * <p>"Dafny" is the AES-256 vector in the Dafny primitives' TestAES.dfy. The other
 * three are test cases 4, 10 and 16 of McGrew and Viega, "The Galois/Counter Mode
 * of Operation (GCM)": the same 60-byte plaintext, 20-byte AAD and 12-byte IV
 * under a 128-, 192- and 256-bit key, one per model algorithm.
 */
public class AesGcmKnownAnswerTest {

    private static final String GCM_SPEC_PLAINTEXT =
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    private static final String GCM_SPEC_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    private static final String GCM_SPEC_IV = "cafebabefacedbaddecaf888";

    record Vector(String name, AesAlgorithm algorithm, String key, String iv, String plaintext,
            String aad, String ciphertext, String tag) {
        @Override
        public String toString() {
            return name;
        }
    }

    static final List<Vector> VECTORS = List.of(
        new Vector("Dafny AES-256", AesAlgorithm.AES_256_GCM,
            "0101010101010101010101010101010101010101010101010101010101010101",
            "020202020202020202020202",
            "61736466",
            "03030303",
            "66a5ad2f",
            "36c81238acc2ae17ef972fb48fe88eb8"),
        new Vector("GCM spec TC4 AES-128", AesAlgorithm.AES_128_GCM,
            "feffe9928665731c6d6a8f9467308308",
            GCM_SPEC_IV, GCM_SPEC_PLAINTEXT, GCM_SPEC_AAD,
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47"),
        new Vector("GCM spec TC10 AES-192", AesAlgorithm.AES_192_GCM,
            "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            GCM_SPEC_IV, GCM_SPEC_PLAINTEXT, GCM_SPEC_AAD,
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
                + "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
            "2519498e80f1478f37ba55bd6d27618c"),
        new Vector("GCM spec TC16 AES-256", AesAlgorithm.AES_256_GCM,
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            GCM_SPEC_IV, GCM_SPEC_PLAINTEXT, GCM_SPEC_AAD,
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b"));

    static Stream<Arguments> cases() {
        return LanguageServerRegistry.shared().targets().stream()
            .flatMap(target -> VECTORS.stream().map(vector -> Arguments.of(vector, target)));
    }

    @ParameterizedTest(name = "[aes-gcm] encrypt {0} {1}")
    @MethodSource("cases")
    void encryptKnownAnswer(Vector vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("aes-gcm"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        AesEncryptOutput out = PrimitivesTestServerClients.withRetry(() ->
            client.aesEncrypt(AesEncryptInput.builder()
                .algorithm(vector.algorithm())
                .key(Bytes.buf(vector.key()))
                .iv(Bytes.buf(vector.iv()))
                .message(Bytes.buf(vector.plaintext()))
                .aad(Bytes.buf(vector.aad()))
                .build()));

        assertArrayEquals(Bytes.hex(vector.ciphertext()), Bytes.of(out.getCiphertext()));
        assertArrayEquals(Bytes.hex(vector.tag()), Bytes.of(out.getAuthTag()));
    }

    @ParameterizedTest(name = "[aes-gcm] decrypt {0} {1}")
    @MethodSource("cases")
    void decryptKnownAnswer(Vector vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("aes-gcm"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] plaintext = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.aesDecrypt(AesDecryptInput.builder()
                .algorithm(vector.algorithm())
                .key(Bytes.buf(vector.key()))
                .iv(Bytes.buf(vector.iv()))
                .ciphertext(Bytes.buf(vector.ciphertext()))
                .authTag(Bytes.buf(vector.tag()))
                .aad(Bytes.buf(vector.aad()))
                .build())).getPlaintext());

        assertArrayEquals(Bytes.hex(vector.plaintext()), plaintext);
    }
}
