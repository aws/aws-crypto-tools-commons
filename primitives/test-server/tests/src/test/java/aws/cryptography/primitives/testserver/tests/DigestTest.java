package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.DigestInput;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.PrimitivesInputs;
import aws.cryptography.testserver.tests.PrimitivesInputs.DigestVector;
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
 *
 * <p>The vectors are in {@link PrimitivesInputs#digestVectors()}.
 * When fuzzing is on, it adds random ones whose expected digest comes from the JDK.
 */
public class DigestTest {

    static Stream<Arguments> cases() {
        return ExampleCases.withEachLanguageServer(PrimitivesInputs.digestVectors());
    }

    @ParameterizedTest(name = "[digest] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Example<DigestVector> vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("digest"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] digest = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.digest(DigestInput.builder()
                .algorithm(DigestAlgorithm.from(vector.value().algorithm()))
                .data(Bytes.buf(vector.value().data()))
                .build())).getDigest());

        assertArrayEquals(Bytes.hex(vector.value().digest()), digest);
    }
}
