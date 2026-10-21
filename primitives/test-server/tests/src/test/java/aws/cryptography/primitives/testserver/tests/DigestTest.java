package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.DigestInput;
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
 * Digest known answers, per target. Every server must produce the same bytes,
 * so a pair adds nothing: each target is checked against the expected value.
 *
 * <p>The "asdf" vectors are the ones in the Dafny primitives' TestDigest.dfy;
 * the "abc" vectors are FIPS 180-2's.
 */
public class DigestTest {

    /** "asdf" */
    private static final String ASDF = "61736466";
    /** "abc" */
    private static final String ABC = "616263";

    record Vector(String name, DigestAlgorithm algorithm, String data, String digest) {
        @Override
        public String toString() {
            return name;
        }
    }

    static final List<Vector> VECTORS = List.of(
        new Vector("SHA-256 asdf", DigestAlgorithm.SHA_256, ASDF,
            "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"),
        new Vector("SHA-384 asdf", DigestAlgorithm.SHA_384, ASDF,
            "a69e7df30b24c042ec540ccbbdbfb1562c85787038c885749c1e408e2d62fa36"
                + "642cd0075fa351e822e2b8a59139cd9d"),
        new Vector("SHA-512 asdf", DigestAlgorithm.SHA_512, ASDF,
            "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429080f"
                + "b337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1"),
        new Vector("SHA-256 abc", DigestAlgorithm.SHA_256, ABC,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        new Vector("SHA-384 abc", DigestAlgorithm.SHA_384, ABC,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                + "8086072ba1e7cc2358baeca134c825a7"),
        new Vector("SHA-512 abc", DigestAlgorithm.SHA_512, ABC,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));

    static Stream<Arguments> cases() {
        return LanguageServerRegistry.shared().targets().stream()
            .flatMap(target -> VECTORS.stream().map(vector -> Arguments.of(vector, target)));
    }

    @ParameterizedTest(name = "[digest] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Vector vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("digest"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] digest = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.digest(DigestInput.builder()
                .algorithm(vector.algorithm())
                .data(Bytes.buf(vector.data()))
                .build())).getDigest());

        assertArrayEquals(Bytes.hex(vector.digest()), digest);
    }
}
