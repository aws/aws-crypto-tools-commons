package aws.cryptography.esdk.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the subprocess launch path's port binding and conflict
 * behavior (design Testing Strategy; Requirements 2.1, 2.5, 2.6). These launch
 * a real subprocess that binds the configured port (a minimal stand-in server
 * — {@code python3 -m http.server}), so they exercise actual port binding,
 * TCP-connect readiness, and process-tree teardown rather than a stub. The
 * in-process Java launcher these tests previously exercised was deleted in
 * task 6.4: every Language_Server now launches as a subprocess.
 */
class PortBindingIntegrationTest {

    private static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** A minimal real server subprocess that binds {@code port} on loopback. */
    private static ProcessBuilder fakeServer(int port) {
        return new ProcessBuilder(
            "python3", "-m", "http.server", String.valueOf(port), "--bind", "127.0.0.1");
    }

    @Test
    @DisplayName("launches a server subprocess bound to its configured port and stops it cleanly (Req 2.1, 2.6)")
    void launchesOnConfiguredPort() throws IOException, ServerLaunchException {
        int port = freePort();
        SubprocessLauncher launcher = new SubprocessLauncher(Duration.ofSeconds(30));
        LaunchedServer server = launcher.launch("java", port, fakeServer(port));
        try {
            assertEquals(port, server.port(), "server must bind the configured port");
            assertEquals(port, server.endpoint().getPort(), "endpoint must expose the configured port");
            // Confirm something is actually listening on the port.
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 5000);
                assertTrue(socket.isConnected(), "the launched server must accept connections");
            }
        } finally {
            CloseResult close = server.close();
            assertEquals(CloseResult.stopped(), close,
                "teardown must kill the process tree and free the port (Req 2.6)");
        }
    }

    @Test
    @DisplayName("surfaces a pre-bound port as a PORT launch failure naming the language (Req 2.5)")
    void surfacesPortConflict() throws IOException {
        int port = freePort();
        // Pre-bind the port to force a conflict when the launcher probes it.
        try (ServerSocket hold = new ServerSocket()) {
            hold.setReuseAddress(false);
            hold.bind(new InetSocketAddress("127.0.0.1", port));

            SubprocessLauncher launcher = new SubprocessLauncher(Duration.ofSeconds(5));
            ServerLaunchException ex = assertThrows(ServerLaunchException.class,
                () -> launcher.launch("java", port, fakeServer(port)),
                "binding an already-used port must abort");
            assertEquals(ServerLaunchException.Category.PORT, ex.category());
            assertEquals("java", ex.language(), "the abort must name the offending language");
            assertTrue(ex.getMessage().contains(String.valueOf(port)),
                "the abort must identify the conflicting port");
        }
    }
}
