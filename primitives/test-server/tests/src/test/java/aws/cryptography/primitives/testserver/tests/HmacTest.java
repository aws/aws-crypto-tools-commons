package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.HmacInput;
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
 * HMAC known answers, per target. The vectors are the two sets in the Dafny
 * primitives' TestHMAC.dfy (key 01010101) and TestAwsCryptographyPrimitivesHMAC.dfy
 * (key 01020304), both over the message "asdf".
 */
public class HmacTest {

    /** "asdf" */
    private static final String ASDF = "61736466";

    record Vector(String name, DigestAlgorithm algorithm, String key, String message, String digest) {
        @Override
        public String toString() {
            return name;
        }
    }

    static final List<Vector> VECTORS = List.of(
        new Vector("SHA-256 key 01010101", DigestAlgorithm.SHA_256, "01010101", ASDF,
            "5d0c56917befa948c3e2ccb3675ec3538680e2b9b8cb62647320072cac0b5110"),
        new Vector("SHA-384 key 01010101", DigestAlgorithm.SHA_384, "01010101", ASDF,
            "db2c333cd939bad0084573b9be888801458f9794074295c110e133555cb08bf9"
                + "385dbd0b9615873699254c44464d9a7c"),
        new Vector("SHA-512 key 01010101", DigestAlgorithm.SHA_512, "01010101", ASDF,
            "31d515db17a9c327b1010fa2e9b6d054e2031b784b4e552edc05a6ce4f2f195e"
                + "5877d3c09417fc9b62da61e1265d53718b5f65de9a62f4ce58e50673e2bc98ad"),
        new Vector("SHA-256 key 01020304", DigestAlgorithm.SHA_256, "01020304", ASDF,
            "376bbaf133ff9aa96a8502f836e6c193d4b39a422b346cb5909813657563cc86"),
        new Vector("SHA-384 key 01020304", DigestAlgorithm.SHA_384, "01020304", ASDF,
            "5aceea51ad4ceb94cb8bc32efb0e616e92319318f00111e73a68923590a70b70"
                + "07277a0f3a35905b10df33621e5817a6"),
        new Vector("SHA-512 key 01020304", DigestAlgorithm.SHA_512, "01020304", ASDF,
            "6417add7274333a595355754913add9befb6f98693bf8fe08ca5beddb70f0666"
                + "cb4dee400a8a3d40db4ff8f95a66d9bc0d026560d9f249febed98621a38997b7"));

    static Stream<Arguments> cases() {
        return LanguageServerRegistry.shared().targets().stream()
            .flatMap(target -> VECTORS.stream().map(vector -> Arguments.of(vector, target)));
    }

    @ParameterizedTest(name = "[hmac] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Vector vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("hmac"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] digest = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.hmac(HmacInput.builder()
                .algorithm(vector.algorithm())
                .key(Bytes.buf(vector.key()))
                .message(Bytes.buf(vector.message()))
                .build())).getDigest());

        assertArrayEquals(Bytes.hex(vector.digest()), digest);
    }
}
