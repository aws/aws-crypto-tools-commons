package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.EcdsaAlgorithm;
import aws.cryptography.primitives.testserver.client.model.EcdsaGenerateKeyPairInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaGenerateKeyPairOutput;
import aws.cryptography.primitives.testserver.client.model.EcdsaSignInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaVerifyInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ECDSA across the pairwise matrix, for P-256 and P-384: generate + sign on the
 * encrypt target, verify on the decrypt target. Ports the Dafny primitives'
 * TestSignature.dfy: YCompression256/384 (the key-shape assertions) and
 * VerifyMessage256/384 (verify succeeds, and fails for message + [1]), plus a
 * tampered-signature case.
 */
public class EcdsaRoundTripTest {

    /** "Hello, World!", the TestSignature.dfy message. */
    private static final byte[] MESSAGE = "Hello, World!".getBytes();

    static Stream<Arguments> pairsByAlgorithm() {
        List<TargetPair> pairs = LanguageServerRegistry.shared().pairs();
        return EcdsaAlgorithm.values().stream()
            .flatMap(algorithm -> pairs.stream().map(pair -> Arguments.of(algorithm, pair)));
    }

    /** @return the X9.62 compressed point length: 1 prefix byte + the field size in bytes. */
    static int compressedKeyLength(EcdsaAlgorithm algorithm) {
        return switch (algorithm.getValue()) {
            case "ECDSA_P256" -> 1 + 32;
            case "ECDSA_P384" -> 1 + 48;
            default -> throw new IllegalArgumentException("unknown ECDSA algorithm " + algorithm);
        };
    }

    @ParameterizedTest(name = "[ecdsa] generated key shape {0} {1}")
    @MethodSource("pairsByAlgorithm")
    void generatedKeyIsCompressed(EcdsaAlgorithm algorithm, TargetPair pair) {
        FeatureGate.require(Set.of("ecdsa"), pair);
        EcdsaGenerateKeyPairOutput keyPair = generate(pair, algorithm);

        byte[] verificationKey = Bytes.of(keyPair.getVerificationKey());
        assertEquals(compressedKeyLength(algorithm), verificationKey.length);
        assertTrue(verificationKey[0] == 0x02 || verificationKey[0] == 0x03,
            "verification key must be a compressed point (prefix 02 or 03)");
        assertTrue(keyPair.getSigningKey().remaining() > 0, "signing key must not be empty");
    }

    @ParameterizedTest(name = "[ecdsa] round-trip {0} {1}")
    @MethodSource("pairsByAlgorithm")
    void ecdsaRoundTrip(EcdsaAlgorithm algorithm, TargetPair pair) {
        FeatureGate.require(Set.of("ecdsa"), pair);
        EcdsaGenerateKeyPairOutput keyPair = generate(pair, algorithm);
        byte[] signature = sign(pair, algorithm, keyPair, MESSAGE);

        assertTrue(verify(pair, algorithm, keyPair, MESSAGE, signature), "signature must verify");

        byte[] extended = Arrays.copyOf(MESSAGE, MESSAGE.length + 1);
        extended[MESSAGE.length] = 1;
        assertFalse(verify(pair, algorithm, keyPair, extended, signature),
            "message + [1] must not verify");
    }

    @ParameterizedTest(name = "[ecdsa] tampered signature rejected {0} {1}")
    @MethodSource("pairsByAlgorithm")
    void tamperedSignatureRejected(EcdsaAlgorithm algorithm, TargetPair pair) {
        FeatureGate.require(Set.of("ecdsa"), pair);
        EcdsaGenerateKeyPairOutput keyPair = generate(pair, algorithm);
        byte[] signature = sign(pair, algorithm, keyPair, MESSAGE);

        // The last byte is the low byte of s, so the DER structure stays well formed.
        byte[] tampered = Bytes.flip(signature, signature.length - 1);
        assertFalse(verify(pair, algorithm, keyPair, MESSAGE, tampered),
            "a tampered signature must not verify");
    }

    private static EcdsaGenerateKeyPairOutput generate(TargetPair pair, EcdsaAlgorithm algorithm) {
        PrimitivesTestServerClient signer =
            PrimitivesTestServerClients.forEndpoint(pair.encryptEndpoint());
        return PrimitivesTestServerClients.withRetry(() ->
            signer.ecdsaGenerateKeyPair(EcdsaGenerateKeyPairInput.builder()
                .algorithm(algorithm)
                .build()));
    }

    private static byte[] sign(TargetPair pair, EcdsaAlgorithm algorithm,
            EcdsaGenerateKeyPairOutput keyPair, byte[] message) {
        PrimitivesTestServerClient signer =
            PrimitivesTestServerClients.forEndpoint(pair.encryptEndpoint());
        return Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            signer.ecdsaSign(EcdsaSignInput.builder()
                .algorithm(algorithm)
                .signingKey(keyPair.getSigningKey())
                .message(ByteBuffer.wrap(message))
                .build())).getSignature());
    }

    private static boolean verify(TargetPair pair, EcdsaAlgorithm algorithm,
            EcdsaGenerateKeyPairOutput keyPair, byte[] message, byte[] signature) {
        PrimitivesTestServerClient verifier =
            PrimitivesTestServerClients.forEndpoint(pair.decryptEndpoint());
        return PrimitivesTestServerClients.withRetry(() ->
            verifier.ecdsaVerify(EcdsaVerifyInput.builder()
                .algorithm(algorithm)
                .verificationKey(keyPair.getVerificationKey())
                .message(ByteBuffer.wrap(message))
                .signature(ByteBuffer.wrap(signature))
                .build())).isValid();
    }
}
