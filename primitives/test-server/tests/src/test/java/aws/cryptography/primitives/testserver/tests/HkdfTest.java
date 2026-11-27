package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.HkdfInput;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.PrimitivesInputs;
import aws.cryptography.testserver.tests.PrimitivesInputs.HkdfVector;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * HKDF (extract + expand) known answers, per target, from RFC 5869 Appendix A
 * test cases 1-3 (the vectors in the Dafny primitives' TestHKDF_Rfc5869TestVectors.dfy;
 * TestAwsCryptographyPrimitivesHKDF.dfy's TestCase1 is A.1).
 *
 * <p>The model limits {@code expectedLength} to 16, 24 or 32, so each vector is
 * checked at those lengths against a prefix of the RFC's 42/82-byte OKM. HKDF-Expand
 * output blocks T(1), T(2)... do not depend on L, so the first n bytes of the
 * RFC's OKM are the OKM for length n.
 *
 * <p>The vectors are in {@link PrimitivesInputs#hkdfVectors()}.
 * When fuzzing is on, it adds random ones whose expected output comes from the JDK.
 */
public class HkdfTest {

    static Stream<Arguments> cases() {
        return ExampleCases.withEachLanguageServer(PrimitivesInputs.hkdfVectors());
    }

    @ParameterizedTest(name = "[hkdf] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Example<HkdfVector> vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("hkdf"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] okm = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.hkdf(HkdfInput.builder()
                .algorithm(DigestAlgorithm.from(vector.value().algorithm()))
                .ikm(Bytes.buf(vector.value().ikm()))
                .salt(Bytes.buf(vector.value().salt()))
                .info(Bytes.buf(vector.value().info()))
                .expectedLength(vector.value().length())
                .build())).getOkm());

        assertArrayEquals(Bytes.hex(vector.value().okm()), okm);
    }
}
