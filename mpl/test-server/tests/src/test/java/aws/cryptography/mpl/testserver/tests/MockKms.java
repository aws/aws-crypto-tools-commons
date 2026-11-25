package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.model.KmsClientConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;

/**
 * A KMS endpoint that answers GenerateDataKey, Encrypt and Decrypt with the
 * replies a test scripts, and saves every request it receives.
 *
 * <p>Real KMS only sends well-formed replies for its own keys. This lets a test
 * hand a keyring a reply whose values are wrong, and check exactly what the
 * keyring asked KMS for.
 *
 * <p>A test scripts the reply for a KMS call right before the keyring call that makes it:
 * <pre>{@code
 * mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
 * keyring.onEncrypt(materials);
 * mockKms.nextGenerateDataKeyFailsWith("NotFoundException");
 * keyring.onEncryptFailsWith(materials, expectedError);
 * }</pre>
 * Each {@code next...} method adds one reply after the replies not used yet for that operation.
 * So when one keyring call makes several KMS calls, the test scripts their replies in order.
 * A request with no reply left gets a 400 error, so the keyring sees a failed KMS call.
 *
 * <p>When a test does not check a reply's data key or ciphertext, MockKms fills in
 * {@link #DATA_KEY} and {@link #CIPHERTEXT}.
 *
 * <p>MockKms speaks KMS's awsJson1_1 protocol and ignores request signatures.
 */
final class MockKms implements AutoCloseable {

    private static final String GENERATE_DATA_KEY = "GenerateDataKey";
    private static final String ENCRYPT = "Encrypt";
    private static final String DECRYPT = "Decrypt";

    /** The data key in a reply whose data key the test does not choose. 32 bytes fits an AES-256 suite. */
    private static final byte[] DATA_KEY = filled(32, 9);
    /** The ciphertext in a reply whose ciphertext the test does not choose. */
    private static final byte[] CIPHERTEXT = filled(64, 9);

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TARGET_PREFIX = "TrentService.";

    /** One request as the keyring sent it: the operation and its JSON body. */
    record Request(String operation, JsonNode body) {
        String text(String field) {
            JsonNode value = body.get(field);
            return value == null || value.isNull() ? null : value.asText();
        }

        byte[] blob(String field) {
            String value = text(field);
            return value == null ? null : Base64.getDecoder().decode(value);
        }

        Map<String, String> stringMap(String field) {
            Map<String, String> out = new HashMap<>();
            JsonNode value = body.get(field);
            if (value != null) {
                value.fields().forEachRemaining(e -> out.put(e.getKey(), e.getValue().asText()));
            }
            return out;
        }

        List<String> stringList(String field) {
            List<String> out = new ArrayList<>();
            JsonNode value = body.get(field);
            if (value != null) {
                value.forEach(item -> out.add(item.asText()));
            }
            return out;
        }
    }

    /** A scripted reply: a 200 body, or a 400 error of a KMS error type. */
    private record Reply(int status, Map<String, Object> body) {
        static Reply success(String keyId, Map<String, Object> fields) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("KeyId", keyId);
            body.putAll(fields);
            return new Reply(200, body);
        }

        /** Never a 5xx, which SDKs retry. */
        static Reply error(String type) {
            return new Reply(400, Map.of("__type", type, "message", "MockKms scripted " + type));
        }
    }

    private final HttpServer server;
    private final Map<String, Queue<Reply>> replies = new HashMap<>();
    private final List<Request> requests = new ArrayList<>();

    MockKms() {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/", this::handle);
        server.start();
    }

    /** The next GenerateDataKey call returns {@link #DATA_KEY} under {@code keyId}. */
    void nextGenerateDataKeyReturnsDataKeyFor(String keyId) {
        nextGenerateDataKeyReturns(keyId, DATA_KEY, CIPHERTEXT);
    }

    /** The next GenerateDataKey call returns {@code plaintext} under {@code keyId}. */
    void nextGenerateDataKeyReturns(String keyId, byte[] plaintext) {
        nextGenerateDataKeyReturns(keyId, plaintext, CIPHERTEXT);
    }

    /** The next GenerateDataKey call returns {@code plaintext} and {@code ciphertext} under {@code keyId}. */
    void nextGenerateDataKeyReturns(String keyId, byte[] plaintext, byte[] ciphertext) {
        add(GENERATE_DATA_KEY, Reply.success(keyId, Map.of(
            "Plaintext", base64(plaintext),
            "CiphertextBlob", base64(ciphertext))));
    }

    /** The next GenerateDataKey call fails with the KMS error {@code errorCode}, such as NotFoundException. */
    void nextGenerateDataKeyFailsWith(String errorCode) {
        add(GENERATE_DATA_KEY, Reply.error(errorCode));
    }

    /** The next Encrypt call returns {@link #CIPHERTEXT} under {@code keyId}. */
    void nextEncryptReturnsCiphertextFor(String keyId) {
        nextEncryptReturns(keyId, CIPHERTEXT);
    }

    /** The next Encrypt call returns {@code ciphertext} under {@code keyId}. */
    void nextEncryptReturns(String keyId, byte[] ciphertext) {
        add(ENCRYPT, Reply.success(keyId, Map.of(
            "CiphertextBlob", base64(ciphertext),
            "EncryptionAlgorithm", "SYMMETRIC_DEFAULT")));
    }

    /** The next Encrypt call fails with the KMS error {@code errorCode}. */
    void nextEncryptFailsWith(String errorCode) {
        add(ENCRYPT, Reply.error(errorCode));
    }

    /** The next Decrypt call returns {@link #DATA_KEY} under {@code keyId}. */
    void nextDecryptReturnsDataKeyFor(String keyId) {
        nextDecryptReturns(keyId, DATA_KEY);
    }

    /** The next Decrypt call returns {@code plaintext} under {@code keyId}. */
    void nextDecryptReturns(String keyId, byte[] plaintext) {
        add(DECRYPT, Reply.success(keyId, Map.of(
            "Plaintext", base64(plaintext),
            "EncryptionAlgorithm", "SYMMETRIC_DEFAULT")));
    }

    /** The next Decrypt call fails with the KMS error {@code errorCode}. */
    void nextDecryptFailsWith(String errorCode) {
        add(DECRYPT, Reply.error(errorCode));
    }

    /** Every GenerateDataKey request so far, in the order received. */
    List<Request> generateDataKeyCalls() {
        return calls(GENERATE_DATA_KEY);
    }

    /** Every Encrypt request so far, in the order received. */
    List<Request> encryptCalls() {
        return calls(ENCRYPT);
    }

    /** Every Decrypt request so far, in the order received. */
    List<Request> decryptCalls() {
        return calls(DECRYPT);
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /**
     * A KMS client for a keyring that sends its KMS calls here.
     * The SDK needs a Region to sign requests, and MockKms ignores signatures.
     */
    KmsClientConfig client() {
        return KmsClientConfig.builder().region("us-west-2").endpoint(endpoint()).build();
    }

    /**
     * The next GenerateDataKey and the next Decrypt both return {@link #DATA_KEY} under {@code keyArn}.
     * That is enough for {@link Keyring#assertEncryptsAndDecrypts()} with an AES-256 suite.
     */
    void allowOneEncryptAndDecrypt(String keyArn) {
        nextGenerateDataKeyReturnsDataKeyFor(keyArn);
        nextDecryptReturnsDataKeyFor(keyArn);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        byte[] requestBody = exchange.getRequestBody().readAllBytes();
        String target = exchange.getRequestHeaders().getFirst("X-Amz-Target");
        String operation = target != null && target.startsWith(TARGET_PREFIX)
            ? target.substring(TARGET_PREFIX.length())
            : String.valueOf(target);
        Reply reply;
        synchronized (this) {
            requests.add(new Request(operation, JSON.readTree(requestBody.length == 0 ? "{}".getBytes(
                StandardCharsets.UTF_8) : requestBody)));
            Queue<Reply> queue = replies.get(operation);
            reply = queue == null ? null : queue.poll();
        }
        if (reply == null) {
            reply = new Reply(400, Map.of("__type", "ValidationException",
                "message", "MockKms has no reply scripted for " + operation));
        }
        byte[] response = JSON.writeValueAsBytes(reply.body());
        exchange.getResponseHeaders().set("Content-Type", "application/x-amz-json-1.1");
        exchange.sendResponseHeaders(reply.status(), response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private synchronized void add(String operation, Reply reply) {
        replies.computeIfAbsent(operation, k -> new ArrayDeque<>()).add(reply);
    }

    private synchronized List<Request> calls(String operation) {
        return requests.stream().filter(r -> r.operation().equals(operation)).toList();
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
