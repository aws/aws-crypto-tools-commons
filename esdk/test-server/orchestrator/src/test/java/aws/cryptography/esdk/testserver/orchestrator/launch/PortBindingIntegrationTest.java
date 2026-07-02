package aws.cryptography.esdk.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedSource;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the {@link JavaServerLauncher}'s port binding and conflict
 * behavior (design Testing Strategy; Requirements 9.4, 9.6). These boot the real
 * in-process Java Language_Server, so they exercise actual port binding rather
 * than a stub.
 */
class PortBindingIntegrationTest {

    private static ConfigurationEntry javaEntry(int port) {
        return new ConfigurationEntry("java", "main", "aws-crypto-tools-java", 3, port);
    }

    private static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("launches the Java server bound to its configured port (Req 9.4)")
    void launchesOnConfiguredPort() throws IOException, ServerLaunchException {
        int port = freePort();
        JavaServerLauncher launcher = new JavaServerLauncher();
        try (LaunchedServer server = launcher.launch(
                javaEntry(port), new ResolvedSource.Head("main", "aws-crypto-tools-java"))) {
            assertEquals(port, server.port(), "server must bind the configured port");
            assertEquals(port, server.endpoint().getPort(), "endpoint must expose the configured port");
            // Confirm something is actually listening on the port.
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 5000);
                assertTrue(socket.isConnected(), "the launched server must accept connections");
            }
        }
    }

    @Test
    @DisplayName("surfaces a port conflict as an abort naming the language (Req 9.6)")
    void surfacesPortConflict() throws IOException {
        int port = freePort();
        // Pre-bind the port to force a conflict when the launcher tries to bind.
        try (ServerSocket hold = new ServerSocket()) {
            hold.setReuseAddress(false);
            hold.bind(new InetSocketAddress("127.0.0.1", port));

            JavaServerLauncher launcher = new JavaServerLauncher();
            ServerLaunchException ex = assertThrows(ServerLaunchException.class,
                () -> launcher.launch(javaEntry(port),
                    new ResolvedSource.Head("main", "aws-crypto-tools-java")),
                "binding an already-used port must abort");
            assertEquals(ServerLaunchException.Category.PORT_CONFLICT, ex.category());
            assertEquals("java", ex.language(), "the abort must name the offending language");
            assertTrue(ex.getMessage().contains(String.valueOf(port)),
                "the abort must identify the conflicting port");
        }
    }
}
