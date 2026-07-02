package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.server.handler.EsdkTestServerHandlers;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.URI;
import software.amazon.smithy.java.server.Server;

/**
 * Boots the generated Java Language_Server in-process over a real HTTP transport
 * (Netty) and exposes its base endpoint URL, so the single {@code Tests} suite
 * can drive a genuine over-the-wire round trip:
 * generated Java Test_Client → HTTP (rpcv2Cbor) → Java Language_Server → real
 * ESDK → back.
 *
 * <p>The service is assembled by reusing {@link EsdkTestServerHandlers#service()}
 * — the same single assembly point the (future) orchestrator/launcher uses — so
 * the checkpoint exercises exactly the wiring shipped by the server module: the
 * smithy-java-generated request decoding / response &amp; error encoding over one
 * shared, thread-safe {@code Client_Registry}, delegating to the real AWS
 * Encryption SDK for Java.
 *
 * <p>The server binds to an ephemeral free port discovered at construction time
 * so parallel/repeated tests never collide on a fixed port. Instances are
 * {@link AutoCloseable}; closing shuts the server down.
 */
public final class LocalJavaLanguageServer implements AutoCloseable {

    private final Server server;
    private final URI endpoint;

    private LocalJavaLanguageServer(Server server, URI endpoint) {
        this.server = server;
        this.endpoint = endpoint;
    }

    /** Boot a Java Language_Server on an ephemeral port and start serving. */
    public static LocalJavaLanguageServer start() {
        int port = freePort();
        EsdkTestServerHandlers handlers = new EsdkTestServerHandlers();
        Server server = Server.builder()
            .endpoints(port)
            .addService(handlers.service())
            .build();
        server.start();
        URI endpoint = URI.create("http://127.0.0.1:" + port);
        return new LocalJavaLanguageServer(server, endpoint);
    }

    /** @return the base endpoint URL the generated Test_Client should target. */
    public URI endpoint() {
        return endpoint;
    }

    @Override
    public void close() {
        server.shutdown().join();
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException("could not allocate a free port for the Java Language_Server", e);
        }
    }
}
