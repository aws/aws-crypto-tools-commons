package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.DecryptOutput;
import aws.cryptography.esdk.testserver.client.model.DecryptStreamInput;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import aws.cryptography.esdk.testserver.client.model.EncryptStreamInput;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Shared single-leg {@code Encrypt}/{@code Decrypt} helpers over the one generated
 * Test_Client, returning {@code byte[]} so a test can hold and inspect (or tamper)
 * the raw ciphertext bytes. Every behavior test class in this package that drives a
 * single encrypt or a single decrypt goes through here, so there is one definition
 * of "create a client on an endpoint, then encrypt/decrypt".
 *
 * <p>This exists because behaviors beyond the round trip — wire-format assertions,
 * byte tampering, trailing-byte and truncation rejection — need the ciphertext as
 * an addressable {@code byte[]} on the test side, not just fed straight back into a
 * decrypt call.
 *
 * <p>Each RPC goes through {@link TestServerClients#withRetry} so a transient
 * transport failure is retried on the test side rather than failing the run.
 */
final class EsdkOps {

    private EsdkOps() {
    }

    /** {@code CreateClient(config)} on {@code endpoint}, returning the client id. */
    static String createClient(URI endpoint, ESDKClientConfig config) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        return clientId(client, config);
    }

    /** Encrypt {@code plaintext} on {@code endpoint} under {@code config}; return the ciphertext bytes. */
    static byte[] encrypt(URI endpoint, ESDKClientConfig config, byte[] plaintext) {
        return encrypt(endpoint, config, plaintext, Map.of(), null, null);
    }

    /**
     * Encrypt {@code plaintext} on {@code endpoint} under {@code config}, applying the
     * optional encryption context, algorithm-suite override, and frame length when
     * supplied; return the ciphertext bytes.
     */
    static byte[] encrypt(URI endpoint, ESDKClientConfig config, byte[] plaintext,
                          Map<String, String> encryptionContext, ESDKAlgorithmSuiteId suite,
                          Long frameLength) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        EncryptInput.Builder input = EncryptInput.builder()
            .clientId(clientId(client, config))
            .plaintext(ByteBuffer.wrap(plaintext));
        if (encryptionContext != null && !encryptionContext.isEmpty()) {
            input.encryptionContext(encryptionContext);
        }
        if (suite != null) {
            input.algorithmSuiteId(suite);
        }
        if (frameLength != null) {
            input.frameLength(frameLength);
        }
        EncryptInput request = input.build();
        return toArray(TestServerClients.withRetry(() -> client.encrypt(request)).getCiphertext());
    }

    /** Decrypt {@code ciphertext} on {@code endpoint} under {@code config}; return the plaintext bytes. */
    static byte[] decrypt(URI endpoint, ESDKClientConfig config, byte[] ciphertext) {
        return decrypt(endpoint, config, ciphertext, Map.of());
    }

    /**
     * Decrypt {@code ciphertext} on {@code endpoint} under {@code config}, supplying the
     * optional reproduced encryption context when non-empty; return the plaintext bytes.
     */
    static byte[] decrypt(URI endpoint, ESDKClientConfig config, byte[] ciphertext,
                          Map<String, String> encryptionContext) {
        return toArray(decryptResponse(endpoint, config, ciphertext, encryptionContext).getPlaintext());
    }

    /**
     * Decrypt {@code ciphertext} on {@code endpoint} under {@code config}, returning the full
     * response so callers can inspect the encryption context and algorithm suite the decryptor
     * exposed (both optional — a Language_Server that does not surface them leaves them null).
     */
    static DecryptOutput decryptResponse(
            URI endpoint, ESDKClientConfig config, byte[] ciphertext,
            Map<String, String> encryptionContext) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        DecryptInput.Builder input = DecryptInput.builder()
            .clientId(clientId(client, config))
            .ciphertext(ByteBuffer.wrap(ciphertext));
        if (encryptionContext != null && !encryptionContext.isEmpty()) {
            input.encryptionContext(encryptionContext);
        }
        DecryptInput request = input.build();
        return TestServerClients.withRetry(() -> client.decrypt(request));
    }

    /** EncryptStream {@code plaintext} on {@code endpoint} under {@code config}; return the ciphertext bytes. */
    static byte[] encryptStream(URI endpoint, ESDKClientConfig config, byte[] plaintext) {
        return encryptStream(endpoint, config, plaintext, null);
    }

    /**
     * EncryptStream {@code plaintext} on {@code endpoint} under {@code config}, applying the
     * optional plaintext-length bound when supplied; return the ciphertext bytes.
     */
    static byte[] encryptStream(URI endpoint, ESDKClientConfig config, byte[] plaintext,
                                Long plaintextLengthBound) {
        return encryptStream(endpoint, config, plaintext, plaintextLengthBound, null);
    }

    /**
     * EncryptStream {@code plaintext} on {@code endpoint} under {@code config}, applying the
     * optional plaintext-length bound and framing length when supplied; return the ciphertext
     * bytes.
     */
    static byte[] encryptStream(URI endpoint, ESDKClientConfig config, byte[] plaintext,
                                Long plaintextLengthBound, Long frameLength) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        EncryptStreamInput.Builder input = EncryptStreamInput.builder()
            .clientId(clientId(client, config))
            .plaintext(ByteBuffer.wrap(plaintext));
        if (plaintextLengthBound != null) {
            input.plaintextLengthBound(plaintextLengthBound);
        }
        if (frameLength != null) {
            input.frameLength(frameLength);
        }
        EncryptStreamInput request = input.build();
        return toArray(TestServerClients.withRetry(() -> client.encryptStream(request)).getCiphertext());
    }

    /** DecryptStream {@code ciphertext} on {@code endpoint} under {@code config}; return the plaintext bytes. */
    static byte[] decryptStream(URI endpoint, ESDKClientConfig config, byte[] ciphertext) {
        ESDKTestServerClient client = TestServerClients.forEndpoint(endpoint);
        DecryptStreamInput request = DecryptStreamInput.builder()
            .clientId(clientId(client, config))
            .ciphertext(ByteBuffer.wrap(ciphertext))
            .build();
        return toArray(TestServerClients.withRetry(() -> client.decryptStream(request)).getPlaintext());
    }

    /** {@code CreateClient(config)} on {@code client}, retried on a transient transport failure. */
    private static String clientId(ESDKTestServerClient client, ESDKClientConfig config) {
        return TestServerClients.withRetry(() ->
            client.createClient(CreateClientInput.builder().config(config).build())).getClientId();
    }

    static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
