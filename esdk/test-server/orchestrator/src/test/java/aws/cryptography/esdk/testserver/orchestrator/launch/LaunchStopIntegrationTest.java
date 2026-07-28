package aws.cryptography.esdk.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Launch/stop integration tests with fake server processes (task 6.5;
 * Requirements 2.5, 2.6, 2.9). These extend — without duplicating — the
 * coverage in {@link SubprocessLauncherTest} (failure categories, including a
 * pre-bound raw socket as a PORT failure) and
 * {@link PortBindingIntegrationTest} (immediate-bind success path and raw
 * pre-bind conflict):
 *
 * <ul>
 *   <li><b>Delayed bind.</b> A fake server that binds its port only after a
 *       delay proves the readiness probe genuinely polls: readiness flips from
 *       unreachable to reachable when — and only when — the port binds, and
 *       the launcher succeeds within its window rather than failing on the
 *       first probe (Requirements 2.5, 2.9).</li>
 *   <li><b>Process-tree teardown.</b> A fake server whose <em>child</em> binds
 *       the port (parent shell → child listener, the Gradle/venv-children
 *       shape) proves {@code close()} kills descendants, not just the spawned
 *       root, and verifies the port is actually free (Requirement 2.6).</li>
 *   <li><b>Held port vs freed port.</b> While a launched fake server holds the
 *       port, a second launch on it is a PORT failure; after teardown reports
 *       STOPPED the same port launches again — the strongest evidence the
 *       port was genuinely released (Requirements 2.5, 2.6).</li>
 * </ul>
 *
 * <p>All fake servers are loopback-only python3/shell one-liners; every wait
 * is bounded by an injectable readiness window, keeping the tests hermetic
 * and fast.
 */
class LaunchStopIntegrationTest {

    /** Generous-but-bounded readiness window for real subprocess startup. */
    private static final Duration READINESS_WINDOW = Duration.ofSeconds(30);

    private static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** @return true iff something on loopback {@code port} accepts a TCP connection. */
    private static boolean acceptsConnection(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 1_000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** A fake server that binds {@code port} immediately (single process). */
    private static ProcessBuilder immediateBindServer(int port) {
        return new ProcessBuilder(
            "python3", "-m", "http.server", String.valueOf(port), "--bind", "127.0.0.1");
    }

    /**
     * A fake server that binds {@code port} only after {@code delay}. The
     * {@code exec} replaces the shell, so the launched process itself becomes
     * the listener — this test isolates the polling behavior from tree shape.
     */
    private static ProcessBuilder delayedBindServer(int port, Duration delay) {
        return new ProcessBuilder("sh", "-c",
            "sleep " + delay.toMillis() / 1000.0
                + "; exec python3 -m http.server " + port + " --bind 127.0.0.1");
    }

    /**
     * A fake server whose <em>child</em> binds {@code port}: the launcher
     * spawns the shell, the shell backgrounds the python listener and waits.
     * The listener is a descendant of the spawned root — the process-tree
     * shape a Gradle or venv launch produces.
     */
    private static ProcessBuilder childBindsPortServer(int port) {
        return new ProcessBuilder("sh", "-c",
            "python3 -m http.server " + port + " --bind 127.0.0.1 & wait");
    }

    @Test
    @DisplayName("readiness genuinely polls: a server that binds after a delay still launches (Req 2.5, 2.9)")
    void delayedBindServerBecomesReady() throws ServerLaunchException {
        int port = freePort();
        Duration bindDelay = Duration.ofMillis(1_500);
        SubprocessLauncher launcher = new SubprocessLauncher(READINESS_WINDOW);

        Instant launchStart = Instant.now();
        LaunchedServer server = launcher.launch("python", port, delayedBindServer(port, bindDelay));
        try {
            Duration untilReady = Duration.between(launchStart, Instant.now());
            // The first probes ran while the port was still unbound: readiness
            // flipping only after the delay proves the probe polled rather
            // than deciding on a single connect attempt.
            assertTrue(untilReady.compareTo(bindDelay) >= 0,
                "launch returned after " + untilReady.toMillis() + "ms, before the fake server's "
                    + bindDelay.toMillis() + "ms bind delay — the readiness probe cannot have polled");
            assertTrue(acceptsConnection(port),
                "after launch() returns, the configured port must accept TCP connections (Req 2.9)");
            assertEquals(port, server.port(), "server must report the configured port");
        } finally {
            assertEquals(CloseResult.stopped(), server.close(),
                "teardown must kill the fake server and free the port (Req 2.6)");
        }
        assertFalse(acceptsConnection(port),
            "after a STOPPED close the port must no longer accept connections (Req 2.6)");
    }

    @Test
    @DisplayName("teardown kills the whole process tree when a child holds the port (Req 2.6)")
    void teardownKillsDescendantHoldingPort() throws ServerLaunchException {
        int port = freePort();
        SubprocessLauncher launcher = new SubprocessLauncher(READINESS_WINDOW);

        // The spawned root is the shell; the actual listener is its child.
        LaunchedServer server = launcher.launch("java", port, childBindsPortServer(port));
        assertTrue(acceptsConnection(port),
            "the child listener must be reachable on the configured port (Req 2.9)");

        CloseResult close = server.close();
        assertEquals(CloseResult.stopped(), close,
            "close() must kill descendants (not just the spawned shell) and verify the port is free");
        assertFalse(acceptsConnection(port),
            "the child listener must be gone after teardown — killing only the root leaks it (Req 2.6)");
        // Idempotence: repeated close reports the first (verified) result.
        assertEquals(CloseResult.stopped(), server.close(), "close() must be idempotent");
    }

    @Test
    @DisplayName("a port held by a launched server is a PORT failure; after STOPPED it launches again (Req 2.5, 2.6)")
    void portHeldByLaunchedServerThenFreedByTeardown() throws ServerLaunchException {
        int port = freePort();
        SubprocessLauncher launcher = new SubprocessLauncher(READINESS_WINDOW);

        LaunchedServer first = launcher.launch("java", port, immediateBindServer(port));
        try {
            // While the first fake server holds the port, launching another
            // server on it is a PORT failure — before anything is spawned.
            ServerLaunchException ex = assertThrows(ServerLaunchException.class,
                () -> launcher.launch("python", port, immediateBindServer(port)));
            assertEquals(ServerLaunchException.Category.PORT, ex.category(),
                "a port held by a live server process is a PORT launch failure (Req 2.5)");
            assertEquals("python", ex.language(), "the abort must name the language");
        } finally {
            assertEquals(CloseResult.stopped(), first.close(),
                "teardown must free the port and report STOPPED (Req 2.6)");
        }

        // The same port is genuinely free: a fresh launch on it succeeds.
        LaunchedServer second = launcher.launch("python", port, immediateBindServer(port));
        try {
            assertTrue(acceptsConnection(port),
                "a relaunch on the freed port must become reachable (Req 2.6, 2.9)");
        } finally {
            assertEquals(CloseResult.stopped(), second.close(),
                "teardown must free the port and report STOPPED (Req 2.6)");
        }
    }
}
