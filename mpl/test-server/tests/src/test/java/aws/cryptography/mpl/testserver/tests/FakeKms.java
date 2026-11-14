package aws.cryptography.mpl.testserver.tests;

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
 * <p>It speaks KMS's awsJson1_1 protocol and ignores request signatures.
 * Replies are used in order, per operation. A request with no reply left is
 * answered with a 400 error, so the keyring sees a failed KMS call.
 */
final class FakeKms implements AutoCloseable {

    static final String GENERATE_DATA_KEY = "GenerateDataKey";
    static final String ENCRYPT = "Encrypt";
    static final String DECRYPT = "Decrypt";

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
    record Reply(int status, Map<String, Object> body) {
        /** A GenerateDataKey reply. */
        static Reply generateDataKey(String keyId, byte[] plaintext, byte[] ciphertext) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("KeyId", keyId);
            body.put("Plaintext", base64(plaintext));
            body.put("CiphertextBlob", base64(ciphertext));
            return new Reply(200, body);
        }

        /** An Encrypt reply. */
        static Reply encrypt(String keyId, byte[] ciphertext) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("KeyId", keyId);
            body.put("CiphertextBlob", base64(ciphertext));
            body.put("EncryptionAlgorithm", "SYMMETRIC_DEFAULT");
            return new Reply(200, body);
        }

        /** A Decrypt reply. */
        static Reply decrypt(String keyId, byte[] plaintext) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("KeyId", keyId);
            body.put("Plaintext", base64(plaintext));
            body.put("EncryptionAlgorithm", "SYMMETRIC_DEFAULT");
            return new Reply(200, body);
        }

        /** A KMS error such as NotFoundException. Never a 5xx, which SDKs retry. */
        static Reply error(String type) {
            return new Reply(400, Map.of("__type", type, "message", "FakeKms scripted " + type));
        }
    }

    private final HttpServer server;
    private final Map<String, Queue<Reply>> replies = new HashMap<>();
    private final List<Request> requests = new ArrayList<>();

    FakeKms() {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/", this::handle);
        server.start();
    }

    /** Add {@code reply} after any replies already scripted for {@code operation}. */
    synchronized FakeKms reply(String operation, Reply reply) {
        replies.computeIfAbsent(operation, k -> new ArrayDeque<>()).add(reply);
        return this;
    }

    /** Every request for {@code operation}, in the order received. */
    synchronized List<Request> requests(String operation) {
        return requests.stream().filter(r -> r.operation().equals(operation)).toList();
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
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
                "message", "FakeKms has no reply scripted for " + operation));
        }
        byte[] response = JSON.writeValueAsBytes(reply.body());
        exchange.getResponseHeaders().set("Content-Type", "application/x-amz-json-1.1");
        exchange.sendResponseHeaders(reply.status(), response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
