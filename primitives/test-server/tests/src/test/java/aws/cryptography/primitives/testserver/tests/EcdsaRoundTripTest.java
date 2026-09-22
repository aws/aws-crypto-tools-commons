package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.EcdsaAlgorithm;
import aws.cryptography.primitives.testserver.client.model.EcdsaGenerateKeyPairInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaGenerateKeyPairOutput;
import aws.cryptography.primitives.testserver.client.model.EcdsaSignInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaSignOutput;
import aws.cryptography.primitives.testserver.client.model.EcdsaVerifyInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaVerifyOutput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ECDSA round-trip: generate + sign on the encrypt target, verify on the
 * decrypt target.
 */
public class EcdsaRoundTripTest {

    private static final byte[] MESSAGE = "ECDSA cross-language test message".getBytes();

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    @ParameterizedTest(name = "[ecdsa-p384] round-trip {0}")
    @MethodSource("pairs")
    void ecdsaP384RoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of("ecdsa"), pair);
        PrimitivesTestServerClient signer =
            PrimitivesTestServerClients.forEndpoint(pair.encryptEndpoint());
        PrimitivesTestServerClient verifier =
            PrimitivesTestServerClients.forEndpoint(pair.decryptEndpoint());

        EcdsaGenerateKeyPairOutput keyPair = PrimitivesTestServerClients.withRetry(() ->
            signer.ecdsaGenerateKeyPair(EcdsaGenerateKeyPairInput.builder()
                .algorithm(EcdsaAlgorithm.ECDSA_P384)
                .build()));

        assertNotNull(keyPair.getSigningKey());
        assertNotNull(keyPair.getVerificationKey());
        assertEquals(49, keyPair.getVerificationKey().remaining()); // compressed P-384

        EcdsaSignOutput signOut = PrimitivesTestServerClients.withRetry(() ->
            signer.ecdsaSign(EcdsaSignInput.builder()
                .algorithm(EcdsaAlgorithm.ECDSA_P384)
                .signingKey(keyPair.getSigningKey())
                .message(ByteBuffer.wrap(MESSAGE))
                .build()));

        assertNotNull(signOut.getSignature());

        EcdsaVerifyOutput verifyOut = PrimitivesTestServerClients.withRetry(() ->
            verifier.ecdsaVerify(EcdsaVerifyInput.builder()
                .algorithm(EcdsaAlgorithm.ECDSA_P384)
                .verificationKey(keyPair.getVerificationKey())
                .message(ByteBuffer.wrap(MESSAGE))
                .signature(signOut.getSignature())
                .build()));

        assertTrue(verifyOut.isValid(), "signature must verify");

        EcdsaVerifyOutput badVerify = PrimitivesTestServerClients.withRetry(() ->
            verifier.ecdsaVerify(EcdsaVerifyInput.builder()
                .algorithm(EcdsaAlgorithm.ECDSA_P384)
                .verificationKey(keyPair.getVerificationKey())
                .message(ByteBuffer.wrap("wrong".getBytes()))
                .signature(signOut.getSignature())
                .build()));

        assertFalse(badVerify.isValid(), "wrong message must not verify");
    }
}
