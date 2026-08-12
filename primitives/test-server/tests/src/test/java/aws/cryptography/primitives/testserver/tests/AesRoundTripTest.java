package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.AesDecryptInput;
import aws.cryptography.primitives.testserver.client.model.AesDecryptOutput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptInput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptOutput;
import aws.cryptography.primitives.testserver.client.model.AesAlgorithm;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AES-GCM round-trip test across the pairwise matrix.
 * Encrypts on server A, decrypts on server B, asserts plaintext matches.
 */
public class AesRoundTripTest {

    private static final byte[] KEY_256 = new byte[32];
    private static final byte[] IV = new byte[12];
    private static final byte[] PLAINTEXT = "hello primitives test-server".getBytes();
    private static final byte[] AAD = "test-aad".getBytes();

    static {
        for (int i = 0; i < KEY_256.length; i++) KEY_256[i] = (byte) i;
        for (int i = 0; i < IV.length; i++) IV[i] = (byte) (i + 100);
    }

    @TestFactory
    Stream<DynamicTest> aes256GcmRoundTrip() {
        List<LanguageServerRegistry.EndpointPair> pairs = LanguageServerRegistry.instance().pairs();
        Assumptions.assumeFalse(pairs.isEmpty(), "No targets configured");

        return pairs.stream().map(pair -> DynamicTest.dynamicTest(
            "AES-256-GCM: encrypt@" + pair.server1().language()
                + " → decrypt@" + pair.server2().language(),
            () -> {
                PrimitivesTestServerClient encryptor = TestServerClients.forEndpoint(pair.server1().endpoint());
                PrimitivesTestServerClient decryptor = TestServerClients.forEndpoint(pair.server2().endpoint());

                // Encrypt
                AesEncryptOutput encOut = encryptor.aesEncrypt(AesEncryptInput.builder()
                    .algorithm(AesAlgorithm.AES_256_GCM)
                    .iv(ByteBuffer.wrap(IV))
                    .key(ByteBuffer.wrap(KEY_256))
                    .message(ByteBuffer.wrap(PLAINTEXT))
                    .aad(ByteBuffer.wrap(AAD))
                    .build());

                assertNotNull(encOut.ciphertext());
                assertNotNull(encOut.authTag());
                assertEquals(16, encOut.authTag().remaining());

                // Decrypt
                AesDecryptOutput decOut = decryptor.aesDecrypt(AesDecryptInput.builder()
                    .algorithm(AesAlgorithm.AES_256_GCM)
                    .key(ByteBuffer.wrap(KEY_256))
                    .ciphertext(encOut.ciphertext())
                    .authTag(encOut.authTag())
                    .iv(ByteBuffer.wrap(IV))
                    .aad(ByteBuffer.wrap(AAD))
                    .build());

                byte[] recovered = new byte[decOut.plaintext().remaining()];
                decOut.plaintext().get(recovered);
                assertArrayEquals(PLAINTEXT, recovered);
            }));
    }
}
