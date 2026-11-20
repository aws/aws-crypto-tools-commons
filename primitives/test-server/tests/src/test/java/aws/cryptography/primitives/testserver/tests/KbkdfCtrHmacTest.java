package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.KbkdfCtrHmacInput;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.ExampleCases;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.PrimitivesInputs;
import aws.cryptography.testserver.tests.PrimitivesInputs.KbkdfVector;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * KBKDF in counter mode with HMAC (NIST SP 800-108 section 4.1, 32-bit
 * big-endian counter before the fixed info) known answers, per target.
 *
 * <p>The vectors are the raw-derive set B.1-B.10 in the Dafny primitives'
 * TestKDF_TestVectors.dfy, where {@code info} is the complete fixed input, which
 * is what the model's {@code info} carries. That file's purpose/nonce set
 * (C.1-C.5) goes through KdfCounterMode, which builds the fixed input itself;
 * the model has no such operation, so those are not ported.
 *
 * <p>The vectors are in {@link PrimitivesInputs#kbkdfVectors()}.
 * When fuzzing is on, it adds random ones whose expected output comes from the JDK.
 */
public class KbkdfCtrHmacTest {

    static Stream<Arguments> cases() {
        return ExampleCases.withEachLanguageServer(PrimitivesInputs.kbkdfVectors());
    }

    @ParameterizedTest(name = "[kbkdf-ctr-hmac] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Example<KbkdfVector> vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("kbkdf-ctr-hmac"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] okm = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.kbkdfCtrHmac(KbkdfCtrHmacInput.builder()
                .algorithm(DigestAlgorithm.from(vector.value().algorithm()))
                .ikm(Bytes.buf(vector.value().ikm()))
                .info(Bytes.buf(vector.value().info()))
                .expectedLength(vector.value().length())
                .build())).getOkm());

        assertArrayEquals(Bytes.hex(vector.value().okm()), okm);
    }
}
