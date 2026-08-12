package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.EcdsaAlgorithm;
import aws.cryptography.primitives.testserver.client.model.EcdsaGenerateKeyPairInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaGenerateKeyPairOutput;
import aws.cryptography.primitives.testserver.client.model.EcdsaSignInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaSignOutput;
import aws.cryptography.primitives.testserver.client.model.EcdsaVerifyInput;
import aws.cryptography.primitives.testserver.client.model.EcdsaVerifyOutput;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ECDSA round-trip: generate on server A, sign on A, verify on server B.
 */
public class EcdsaRoundTripTest {

    private static final byte[] MESSAGE = "ECDSA cross-language test message".getBytes();

    @TestFactory
    Stream<DynamicTest> ecdsaP384RoundTrip() {
        List<LanguageServerRegistry.EndpointPair> pairs = LanguageServerRegistry.instance().pairs();
        Assumptions.assumeFalse(pairs.isEmpty(), "No targets configured");

        return pairs.stream().map(pair -> DynamicTest.dynamicTest(
            "ECDSA-P384: sign@" + pair.server1().language()
                + " → verify@" + pair.server2().language(),
            () -> {
                PrimitivesTestServerClient signer = TestServerClients.forEndpoint(pair.server1().endpoint());
                PrimitivesTestServerClient verifier = TestServerClients.forEndpoint(pair.server2().endpoint());

                // Generate key pair on signer
                EcdsaGenerateKeyPairOutput keyPair = signer.ecdsaGenerateKeyPair(
                    EcdsaGenerateKeyPairInput.builder()
                        .algorithm(EcdsaAlgorithm.ECDSA_P384)
                        .build());

                assertNotNull(keyPair.signingKey());
                assertNotNull(keyPair.verificationKey());
                assertEquals(49, keyPair.verificationKey().remaining()); // compressed P-384

                // Sign
                EcdsaSignOutput signOut = signer.ecdsaSign(EcdsaSignInput.builder()
                    .algorithm(EcdsaAlgorithm.ECDSA_P384)
                    .signingKey(keyPair.signingKey())
                    .message(ByteBuffer.wrap(MESSAGE))
                    .build());

                assertNotNull(signOut.signature());

                // Verify on (possibly different) server
                EcdsaVerifyOutput verifyOut = verifier.ecdsaVerify(EcdsaVerifyInput.builder()
                    .algorithm(EcdsaAlgorithm.ECDSA_P384)
                    .verificationKey(keyPair.verificationKey())
                    .message(ByteBuffer.wrap(MESSAGE))
                    .signature(signOut.signature())
                    .build());

                assertTrue(verifyOut.valid(), "signature must verify");

                // Negative: wrong message
                EcdsaVerifyOutput badVerify = verifier.ecdsaVerify(EcdsaVerifyInput.builder()
                    .algorithm(EcdsaAlgorithm.ECDSA_P384)
                    .verificationKey(keyPair.verificationKey())
                    .message(ByteBuffer.wrap("wrong".getBytes()))
                    .signature(signOut.signature())
                    .build());

                assertFalse(badVerify.valid(), "wrong message must not verify");
            }));
    }
}
