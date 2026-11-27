package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.AesAlgorithm;
import aws.cryptography.primitives.testserver.client.model.AesDecryptInput;
import aws.cryptography.primitives.testserver.client.model.AesDecryptOutput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptInput;
import aws.cryptography.primitives.testserver.client.model.AesEncryptOutput;
import aws.cryptography.primitives.testserver.client.model.PrimitivesError;
import aws.cryptography.testserver.tests.Example;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.PrimitivesInputs;
import aws.cryptography.testserver.tests.PrimitivesInputs.AesGcmMessage;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * AES-GCM across the pairwise matrix: encrypt on the encrypt target, decrypt on
 * the decrypt target. A clean round trip must recover the plaintext for every
 * key size; altering any one authenticated input must make the decrypt fail.
 */
public class AesRoundTripTest {

    private static final byte[] IV = new byte[12];
    private static final byte[] PLAINTEXT = "hello primitives test-server".getBytes();
    private static final byte[] AAD = "test-aad".getBytes();

    static {
        for (int i = 0; i < IV.length; i++) IV[i] = (byte) (i + 100);
    }

    static byte[] key(AesAlgorithm algorithm) {
        int length = switch (algorithm.getValue()) {
            case "AES_128_GCM" -> 16;
            case "AES_192_GCM" -> 24;
            case "AES_256_GCM" -> 32;
            default -> throw new IllegalArgumentException("unknown AES algorithm " + algorithm);
        };
        byte[] key = new byte[length];
        for (int i = 0; i < key.length; i++) key[i] = (byte) i;
        return key;
    }

    /** The arguments are (message, algorithm, pair), so the display name ends with the pair. */
    static Stream<Arguments> messagesByAlgorithm() {
        List<TargetPair> pairs = LanguageServerRegistry.shared().pairs();
        return PrimitivesInputs.aesGcmMessages().stream()
            .flatMap(message -> AesAlgorithm.values().stream()
                .flatMap(algorithm -> pairs.stream().map(pair -> Arguments.of(message, algorithm, pair))));
    }

    /** One altered input to an otherwise valid AesDecrypt request. */
    enum Tamper {
        TAG, CIPHERTEXT, AAD, IV, KEY
    }

    static Stream<Arguments> pairsByTamper() {
        List<TargetPair> pairs = LanguageServerRegistry.shared().pairs();
        return Stream.of(Tamper.values())
            .flatMap(tamper -> pairs.stream().map(pair -> Arguments.of(tamper, pair)));
    }

    @ParameterizedTest(name = "[aes-gcm] round-trip {1} {0} {2}")
    @MethodSource("messagesByAlgorithm")
    void aesGcmRoundTrip(Example<AesGcmMessage> message, AesAlgorithm algorithm, TargetPair pair) {
        FeatureGate.require(Set.of("aes-gcm"), pair);
        PrimitivesTestServerClient decryptor =
            PrimitivesTestServerClients.forEndpoint(pair.decryptEndpoint());
        byte[] key = key(algorithm);
        byte[] plaintext = Bytes.hex(message.value().plaintext());
        byte[] aad = Bytes.hex(message.value().aad());

        AesEncryptOutput encOut = encrypt(pair, algorithm, key, plaintext, aad);
        assertEquals(plaintext.length, encOut.getCiphertext().remaining());
        assertEquals(16, encOut.getAuthTag().remaining());

        AesDecryptOutput decOut = PrimitivesTestServerClients.withRetry(() ->
            decryptor.aesDecrypt(AesDecryptInput.builder()
                .algorithm(algorithm)
                .key(ByteBuffer.wrap(key))
                .ciphertext(encOut.getCiphertext())
                .authTag(encOut.getAuthTag())
                .iv(ByteBuffer.wrap(IV))
                .aad(ByteBuffer.wrap(aad))
                .build()));

        assertArrayEquals(plaintext, Bytes.of(decOut.getPlaintext()));
    }

    @ParameterizedTest(name = "[aes-gcm] tampered {0} rejected {1}")
    @MethodSource("pairsByTamper")
    void tamperedInputRejected(Tamper tamper, TargetPair pair) {
        FeatureGate.require(Set.of("aes-gcm"), pair);
        PrimitivesTestServerClient decryptor =
            PrimitivesTestServerClients.forEndpoint(pair.decryptEndpoint());
        AesAlgorithm algorithm = AesAlgorithm.AES_256_GCM;
        byte[] key = key(algorithm);
        AesEncryptOutput encOut = encrypt(pair, algorithm, key, PLAINTEXT, AAD);

        byte[] tag = Bytes.of(encOut.getAuthTag());
        byte[] ciphertext = Bytes.of(encOut.getCiphertext());
        AesDecryptInput input = AesDecryptInput.builder()
            .algorithm(algorithm)
            .key(ByteBuffer.wrap(tamper == Tamper.KEY ? Bytes.flip(key, 0) : key))
            .ciphertext(ByteBuffer.wrap(tamper == Tamper.CIPHERTEXT ? Bytes.flip(ciphertext, 0) : ciphertext))
            .authTag(ByteBuffer.wrap(tamper == Tamper.TAG ? Bytes.flip(tag, tag.length - 1) : tag))
            .iv(ByteBuffer.wrap(tamper == Tamper.IV ? Bytes.flip(IV, 0) : IV))
            .aad(ByteBuffer.wrap(tamper == Tamper.AAD ? Bytes.flip(AAD, 0) : AAD))
            .build();

        assertThrows(PrimitivesError.class, () -> decryptor.aesDecrypt(input));
    }

    private static AesEncryptOutput encrypt(
            TargetPair pair, AesAlgorithm algorithm, byte[] key, byte[] plaintext, byte[] aad) {
        PrimitivesTestServerClient encryptor =
            PrimitivesTestServerClients.forEndpoint(pair.encryptEndpoint());
        return PrimitivesTestServerClients.withRetry(() ->
            encryptor.aesEncrypt(AesEncryptInput.builder()
                .algorithm(algorithm)
                .iv(ByteBuffer.wrap(IV))
                .key(ByteBuffer.wrap(key))
                .message(ByteBuffer.wrap(plaintext))
                .aad(ByteBuffer.wrap(aad))
                .build()));
    }
}
