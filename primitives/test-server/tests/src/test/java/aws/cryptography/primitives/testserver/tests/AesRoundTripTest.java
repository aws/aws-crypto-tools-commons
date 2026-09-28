package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.AesAlgorithm;
import aws.cryptography.primitives.testserver.client.model.AesDecryptInput;
import aws.cryptography.primitives.testserver.client.model.AesDecryptOutput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptInput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptOutput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * AES-GCM round-trip test across the pairwise matrix.
 * Encrypts on the encrypt target, decrypts on the decrypt target, asserts the
 * plaintext matches.
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

    static List<TargetPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    @ParameterizedTest(name = "[aes-256-gcm] round-trip {0}")
    @MethodSource("pairs")
    void aes256GcmRoundTrip(TargetPair pair) {
        FeatureGate.require(Set.of("aes-gcm"), pair);
        PrimitivesTestServerClient encryptor =
            PrimitivesTestServerClients.forEndpoint(pair.encryptEndpoint());
        PrimitivesTestServerClient decryptor =
            PrimitivesTestServerClients.forEndpoint(pair.decryptEndpoint());

        AesEncryptOutput encOut = PrimitivesTestServerClients.withRetry(() ->
            encryptor.aesEncrypt(AesEncryptInput.builder()
                .algorithm(AesAlgorithm.AES_256_GCM)
                .iv(ByteBuffer.wrap(IV))
                .key(ByteBuffer.wrap(KEY_256))
                .message(ByteBuffer.wrap(PLAINTEXT))
                .aad(ByteBuffer.wrap(AAD))
                .build()));

        assertNotNull(encOut.getCiphertext());
        assertNotNull(encOut.getAuthTag());
        assertEquals(16, encOut.getAuthTag().remaining());

        AesDecryptOutput decOut = PrimitivesTestServerClients.withRetry(() ->
            decryptor.aesDecrypt(AesDecryptInput.builder()
                .algorithm(AesAlgorithm.AES_256_GCM)
                .key(ByteBuffer.wrap(KEY_256))
                .ciphertext(encOut.getCiphertext())
                .authTag(encOut.getAuthTag())
                .iv(ByteBuffer.wrap(IV))
                .aad(ByteBuffer.wrap(AAD))
                .build()));

        byte[] recovered = new byte[decOut.getPlaintext().remaining()];
        decOut.getPlaintext().get(recovered);
        assertArrayEquals(PLAINTEXT, recovered);
    }
}
