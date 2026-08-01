package aws.cryptography.esdk.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the shared {@link SubprocessLauncher} machinery's failure
 * categories (Requirements 2.5, 2.9): a pre-bound port is a PORT failure
 * before anything is spawned; an unstartable or early-exiting process is a
 * BUILD failure; a process that never accepts a connection within the
 * (injectable) readiness window is a TIMEOUT. The success path with a real
 * fake server process is the task 6.5 integration test.
 */
class SubprocessLauncherTest {

    private static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("a pre-bound port is a PORT launch failure before any process is spawned (Req 2.5)")
    void preBoundPortIsPortFailure() throws IOException {
        int port = freePort();
        try (ServerSocket hold = new ServerSocket()) {
            hold.setReuseAddress(false);
            hold.bind(new InetSocketAddress("127.0.0.1", port));

            // The command does not exist: had the launcher spawned before
            // probing, this would surface as BUILD, not PORT.
            ProcessBuilder neverSpawned = new ProcessBuilder("this-command-does-not-exist");
            SubprocessLauncher launcher = new SubprocessLauncher(Duration.ofSeconds(1));

            ServerLaunchException ex = assertThrows(ServerLaunchException.class,
                () -> launcher.launch("python", port, neverSpawned));
            assertEquals(ServerLaunchException.Category.PORT, ex.category(),
                "a pre-existing binder is a PORT launch failure, not flaky readiness");
            assertEquals("python", ex.language(), "the abort must name the language");
            assertTrue(ex.getMessage().contains(String.valueOf(port)),
                "the abort must identify the conflicting port");
        }
    }

    @Test
    @DisplayName("a process that cannot start is a BUILD failure naming the language")
    void unstartableProcessIsBuildFailure() {
        int port = freePort();
        ProcessBuilder unstartable = new ProcessBuilder("this-command-does-not-exist");
        SubprocessLauncher launcher = new SubprocessLauncher(Duration.ofSeconds(1));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> launcher.launch("java", port, unstartable));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertEquals("java", ex.language());
    }

    @Test
    @DisplayName("a process that exits before accepting connections is a BUILD failure")
    void earlyExitIsBuildFailure() {
        int port = freePort();
        // "true" exits 0 immediately and never binds the port.
        ProcessBuilder earlyExit = new ProcessBuilder("true");
        SubprocessLauncher launcher = new SubprocessLauncher(Duration.ofSeconds(30));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> launcher.launch("java", port, earlyExit));
        assertEquals(ServerLaunchException.Category.BUILD, ex.category());
        assertEquals("java", ex.language());
        assertTrue(ex.getMessage().contains(String.valueOf(port)));
    }

    @Test
    @DisplayName("no TCP connect within the readiness window is a TIMEOUT (Req 2.5, 2.9)")
    void readinessTimeoutIsTimeoutFailure() {
        int port = freePort();
        // Stays alive but never binds the port; the injectable window keeps
        // this fast. The launcher kills the spawned tree before aborting.
        ProcessBuilder neverReady = new ProcessBuilder("sleep", "30");
        SubprocessLauncher launcher = new SubprocessLauncher(Duration.ofMillis(600));

        ServerLaunchException ex = assertThrows(ServerLaunchException.class,
            () -> launcher.launch("python", port, neverReady));
        assertEquals(ServerLaunchException.Category.TIMEOUT, ex.category());
        assertEquals("python", ex.language(), "the abort must name the language");
        assertTrue(ex.getMessage().contains(String.valueOf(port)),
            "the abort must identify the unready port");
    }

    @Test
    @DisplayName("the default readiness window is 180s unless the env var is set")
    void defaultReadinessTimeoutWithoutEnvOverride() {
        assertEquals(SubprocessLauncher.DEFAULT_READINESS_TIMEOUT,
            SubprocessLauncher.defaultReadinessTimeout(null));
        assertEquals(SubprocessLauncher.DEFAULT_READINESS_TIMEOUT,
            SubprocessLauncher.defaultReadinessTimeout("  "));
    }

    @Test
    @DisplayName(SubprocessLauncher.READY_TIMEOUT_ENV_VAR + " overrides the default readiness window")
    void envVarOverridesDefaultReadinessTimeout() {
        assertEquals(Duration.ofSeconds(900),
            SubprocessLauncher.defaultReadinessTimeout("900"));
        assertEquals(Duration.ofSeconds(1),
            SubprocessLauncher.defaultReadinessTimeout(" 1 "));
    }

    @Test
    @DisplayName("a non-numeric or non-positive env override is a configuration error naming the variable")
    void malformedEnvOverrideIsConfigurationError() {
        for (String bad : new String[] {"abc", "0", "-5", "1.5"}) {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> SubprocessLauncher.defaultReadinessTimeout(bad));
            assertTrue(ex.getMessage().contains(SubprocessLauncher.READY_TIMEOUT_ENV_VAR),
                "the error must name the environment variable");
            assertTrue(ex.getMessage().contains(bad),
                "the error must carry the rejected value");
        }
    }
}
