package aws.cryptography.mpl.testserver.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;

/**
 * A DynamoDB endpoint that answers every GetItem with one fixed item, whatever
 * key the request names. A real table can only return the item stored under
 * the requested key, so this is how a test hands a key store a record from
 * another slot.
 */
final class FakeDynamoDb implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final byte[] NOT_FOUND = ("{\"__type\":"
        + "\"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException\","
        + "\"message\":\"FakeDynamoDb is set to fail\"}").getBytes(StandardCharsets.UTF_8);

    private final HttpServer server;

    private volatile boolean failing;

    private FakeDynamoDb(Map<String, AttributeValue> item) throws IOException {
        byte[] body = JSON.writeValueAsBytes(Map.of("Item", wire(item)));
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            String target = exchange.getRequestHeaders().getFirst("X-Amz-Target");
            byte[] response = body;
            int status = 200;
            if (failing) {
                status = 400;
                response = NOT_FOUND;
            } else if (!"DynamoDB_20120810.GetItem".equals(target)) {
                status = 400;
                response = ("{\"__type\":\"com.amazon.coral.validate#ValidationException\","
                    + "\"message\":\"FakeDynamoDb only serves GetItem, not " + target + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            }
            exchange.getResponseHeaders().set("Content-Type", "application/x-amz-json-1.0");
            exchange.sendResponseHeaders(status, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
    }

    /** Serve the item stored in {@code table} under the given key. */
    static FakeDynamoDb serving(String region, String table, String branchKeyId, String type) {
        try (DynamoDbClient ddb = DynamoDbClient.builder().region(Region.of(region)).build()) {
            Map<String, AttributeValue> item = ddb.getItem(GetItemRequest.builder()
                .tableName(table)
                .key(Map.of(
                    "branch-key-id", AttributeValue.fromS(branchKeyId),
                    "type", AttributeValue.fromS(type)))
                .consistentRead(true)
                .build()).item();
            if (item == null || item.isEmpty()) {
                throw new IllegalStateException("no item for " + branchKeyId + " / " + type + " in " + table);
            }
            return new FakeDynamoDb(item);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** While {@code failing} is true, answer every request with ResourceNotFoundException. */
    void setFailing(boolean failing) {
        this.failing = failing;
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    /** An item in DynamoDB's JSON wire form. */
    private static Map<String, Object> wire(Map<String, AttributeValue> item) {
        Map<String, Object> out = new LinkedHashMap<>();
        item.forEach((name, value) -> out.put(name, wire(value)));
        return out;
    }

    private static Map<String, Object> wire(AttributeValue value) {
        switch (value.type()) {
            case S: return Map.of("S", value.s());
            case N: return Map.of("N", value.n());
            case B: return Map.of("B", Base64.getEncoder().encodeToString(value.b().asByteArray()));
            case BOOL: return Map.of("BOOL", value.bool());
            case M: return Map.of("M", wire(value.m()));
            default: throw new IllegalArgumentException("unexpected attribute type " + value.type());
        }
    }
}
