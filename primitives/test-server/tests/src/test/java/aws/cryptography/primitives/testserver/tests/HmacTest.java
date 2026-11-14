package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.HmacInput;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.PrimitivesInputs;
import aws.cryptography.testserver.tests.PrimitivesInputs.HmacVector;
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
 *
 * <p>The vectors are in {@link PrimitivesInputs#hmacVectors()}.
 * When fuzzing is on, it adds random ones whose expected HMAC comes from the JDK.
 */
public class HmacTest {

    static Stream<Arguments> cases() {
        return ExampleCases.withEachLanguageServer(PrimitivesInputs.hmacVectors());
    }

    @ParameterizedTest(name = "[hmac] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Example<HmacVector> vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("hmac"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] digest = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.hmac(HmacInput.builder()
                .algorithm(DigestAlgorithm.from(vector.value().algorithm()))
                .key(Bytes.buf(vector.value().key()))
                .message(Bytes.buf(vector.value().message()))
                .build())).getDigest());

        assertArrayEquals(Bytes.hex(vector.value().digest()), digest);
    }
}
