package aws.cryptography.esdk.testserver.orchestrator.launch;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;

/**
 * Loopback TCP port probes shared by the launch machinery.
 *
 * <ul>
 *   <li>Pre-launch availability = the port can still be <em>bound</em>
 *       (catches binders that hold the port without accepting connections); a
 *       pre-existing binder is a {@code PORT} launch failure, not flaky
 *       readiness (design "Launcher contract").</li>
 *   <li>Readiness = the port <em>accepts a TCP connection</em> — the only
 *       reachability signal the orchestrator trusts (Requirement 2.9).</li>
 *   <li>Post-teardown verification = the port no longer accepts connections
 *       (Requirement 2.6), polled briefly since the OS may lag releasing it.</li>
 * </ul>
 */
final class Ports {

    private static final int CONNECT_TIMEOUT_MILLIS = 1_000;
    private static final Duration POLL_INTERVAL = Duration.ofMillis(200);

    private Ports() {
    }

    /** @return true iff a TCP server socket can currently be bound to {@code port} on loopback. */
    static boolean isBindable(int port) {
        try (ServerSocket probe = new ServerSocket()) {
            probe.setReuseAddress(false);
            probe.bind(new InetSocketAddress("127.0.0.1", port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** @return true iff something on loopback {@code port} accepts a TCP connection (Req 2.9). */
    static boolean acceptsConnection(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MILLIS);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Poll until loopback {@code port} no longer accepts TCP connections.
     *
     * @return true iff the port stopped accepting connections within {@code timeout}
     */
    static boolean awaitReleased(int port, Duration timeout) {
        Instant deadline = Instant.now().plus(timeout);
        while (true) {
            if (!acceptsConnection(port)) {
                return true;
            }
            if (!Instant.now().isBefore(deadline)) {
                return false;
            }
            sleep(POLL_INTERVAL);
        }
    }

    /** Interruption-safe sleep; restores the interrupt flag and returns early. */
    static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
